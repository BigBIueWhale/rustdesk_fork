import com.android.emulator.control.Image;
import com.android.emulator.control.ImageFormat;
import com.google.protobuf.ByteString;
import io.grpc.CallOptions;
import io.grpc.ManagedChannel;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.protobuf.ProtoUtils;
import io.grpc.stub.ClientCalls;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class AndroidEmulatorFrameObserver {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 8554;
    private static final int DESIRED_WIDTH = 200;
    private static final int DESIRED_HEIGHT = 200;
    private static final int MAX_FRAME_BYTES = DESIRED_WIDTH * DESIRED_HEIGHT * 3;
    private static final long STARTUP_LIMIT_NANOS = Duration.ofMinutes(15).toNanos();
    private static final long MIN_PUBLICATION_INTERVAL_NANOS =
            Duration.ofMillis(25).toNanos();
    private static final Set<PosixFilePermission> PRIVATE_FILE_PERMISSIONS =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private static final MethodDescriptor<ImageFormat, Image> SCREENSHOT_STREAM =
            MethodDescriptor.<ImageFormat, Image>newBuilder()
                    .setType(MethodDescriptor.MethodType.SERVER_STREAMING)
                    .setFullMethodName(
                            MethodDescriptor.generateFullMethodName(
                                    "android.emulation.control.EmulatorController",
                                    "streamScreenshot"))
                    .setRequestMarshaller(
                            ProtoUtils.marshaller(ImageFormat.getDefaultInstance()))
                    .setResponseMarshaller(ProtoUtils.marshaller(Image.getDefaultInstance()))
                    .build();

    private AndroidEmulatorFrameObserver() {}

    private record Frame(
            long sequence,
            long timestampUs,
            long observedEpochUs,
            long observedMonotonicNs,
            int width,
            int height,
            byte[] pixels) {
        boolean visible() {
            return width > 0 && height > 0;
        }
    }

    private static void requirePrivateDirectory(Path path) throws IOException {
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("observer output root is not one directory");
        }
        Map<String, Object> attributes =
                Files.readAttributes(path, "unix:uid,gid,mode", LinkOption.NOFOLLOW_LINKS);
        int uid = (int) attributes.get("uid");
        int gid = (int) attributes.get("gid");
        int mode = (int) attributes.get("mode");
        if (uid != 1000 || gid != 1000 || (mode & 0777) != 0700) {
            throw new IOException("observer output root metadata differs");
        }
    }

    private static void writeAtomically(Path root, String name, byte[] content)
            throws IOException {
        Path destination = root.resolve(name);
        Path temporary = Files.createTempFile(root, "." + name + ".", ".tmp");
        boolean moved = false;
        try {
            Files.setPosixFilePermissions(temporary, PRIVATE_FILE_PERMISSIONS);
            try (FileChannel channel =
                    FileChannel.open(
                            temporary,
                            StandardOpenOption.WRITE,
                            StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer bytes = ByteBuffer.wrap(content);
                while (bytes.hasRemaining()) {
                    channel.write(bytes);
                }
                channel.force(true);
            }
            try {
                Files.move(
                        temporary,
                        destination,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException error) {
                throw new IOException("observer output filesystem lacks atomic replacement", error);
            }
            moved = true;
        } finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private static Frame validate(Image image, long previousSequence, boolean first) {
        ImageFormat format = image.getFormat();
        if (format.getFormat() != ImageFormat.ImgFormat.RGB888) {
            throw new IllegalArgumentException("emulator returned a non-RGB888 frame");
        }
        int width = format.getWidth();
        int height = format.getHeight();
        ByteString payload = image.getImage();
        long sequence = Integer.toUnsignedLong(image.getSeq());
        if (!first && sequence <= previousSequence) {
            throw new IllegalArgumentException("emulator frame sequence did not increase");
        }
        long timestampUs = image.getTimestampUs();
        if (timestampUs <= 0) {
            throw new IllegalArgumentException("emulator frame has no generation timestamp");
        }
        long observedEpochUs = Math.multiplyExact(System.currentTimeMillis(), 1_000L);
        long observedMonotonicNs = System.nanoTime();
        if (width == 0 && height == 0 && payload.isEmpty()) {
            return new Frame(
                    sequence,
                    timestampUs,
                    observedEpochUs,
                    observedMonotonicNs,
                    0,
                    0,
                    new byte[0]);
        }
        if (!((width == 120 && height == 200) || (width == 200 && height == 120))) {
            throw new IllegalArgumentException("emulator returned unexpected frame dimensions");
        }
        int expectedBytes;
        try {
            expectedBytes = Math.multiplyExact(Math.multiplyExact(width, height), 3);
        } catch (ArithmeticException error) {
            throw new IllegalArgumentException("emulator frame dimensions overflow", error);
        }
        if (expectedBytes <= 0 || expectedBytes > MAX_FRAME_BYTES) {
            throw new IllegalArgumentException("emulator frame exceeds its byte bound");
        }
        if (payload.size() != expectedBytes) {
            throw new IllegalArgumentException("emulator frame byte length differs");
        }
        return new Frame(
                sequence,
                timestampUs,
                observedEpochUs,
                observedMonotonicNs,
                width,
                height,
                payload.toByteArray());
    }

    private static byte[] encode(Frame frame) {
        String header =
                "RUSTDESK_ANDROID_FRAME_V1\n"
                        + "seq="
                        + frame.sequence()
                        + " timestamp_us="
                        + frame.timestampUs()
                        + " observed_epoch_us="
                        + frame.observedEpochUs()
                        + " observed_monotonic_ns="
                        + frame.observedMonotonicNs()
                        + " width="
                        + frame.width()
                        + " height="
                        + frame.height()
                        + " format=rgb888 orientation=bottom-up bytes="
                        + frame.pixels().length
                        + "\n";
        byte[] metadata = header.getBytes(StandardCharsets.US_ASCII);
        byte[] record = new byte[metadata.length + frame.pixels().length];
        System.arraycopy(metadata, 0, record, 0, metadata.length);
        System.arraycopy(frame.pixels(), 0, record, metadata.length, frame.pixels().length);
        return record;
    }

    private static boolean stopRequested(Path stop) {
        if (!Files.exists(stop, LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        try {
            if (!Files.isRegularFile(stop, LinkOption.NOFOLLOW_LINKS)
                    || Files.size(stop) != 5
                    || !Files.readString(stop, StandardCharsets.US_ASCII).equals("stop\n")) {
                throw new IllegalStateException("observer stop marker differs");
            }
            Map<String, Object> attributes =
                    Files.readAttributes(stop, "unix:uid,gid,mode", LinkOption.NOFOLLOW_LINKS);
            if ((int) attributes.get("uid") != 1000
                    || (int) attributes.get("gid") != 1000
                    || ((int) attributes.get("mode") & 0777) != 0600) {
                throw new IllegalStateException("observer stop marker metadata differs");
            }
            return true;
        } catch (IOException error) {
            throw new IllegalStateException("cannot validate observer stop marker", error);
        }
    }

    private static void sleepBeforeRetry(Path stop) throws InterruptedException {
        for (int attempt = 0; attempt < 5 && !stopRequested(stop); attempt++) {
            Thread.sleep(50);
        }
    }

    private static int observe(Path outputRoot) throws Exception {
        requirePrivateDirectory(outputRoot);
        Path stop = outputRoot.resolve("stop");
        Files.deleteIfExists(outputRoot.resolve("latest.frame"));
        Files.deleteIfExists(outputRoot.resolve("ready"));
        Files.deleteIfExists(outputRoot.resolve("failure"));
        Files.deleteIfExists(outputRoot.resolve("stopped"));
        ManagedChannel channel =
                NettyChannelBuilder.forAddress(HOST, PORT)
                        .usePlaintext()
                        .maxInboundMessageSize(MAX_FRAME_BYTES + 64 * 1024)
                        .build();
        ScheduledExecutorService stopWatcher =
                Executors.newSingleThreadScheduledExecutor(
                        runnable -> {
                            Thread thread = new Thread(runnable, "frame-observer-stop");
                            thread.setDaemon(false);
                            return thread;
                        });
        stopWatcher.scheduleWithFixedDelay(
                () -> {
                    try {
                        if (stopRequested(stop)) {
                            channel.shutdownNow();
                        }
                    } catch (RuntimeException error) {
                        channel.shutdownNow();
                    }
                },
                0,
                50,
                TimeUnit.MILLISECONDS);
        long startupDeadline = System.nanoTime() + STARTUP_LIMIT_NANOS;
        long previousSequence = 0;
        long lastPublicationNs = 0;
        long framesReceived = 0;
        long framesPublished = 0;
        boolean receivedAny = false;
        ImageFormat request =
                ImageFormat.newBuilder()
                        .setFormat(ImageFormat.ImgFormat.RGB888)
                        .setWidth(DESIRED_WIDTH)
                        .setHeight(DESIRED_HEIGHT)
                        .setDisplay(0)
                        .build();
        try {
            while (!stopRequested(stop)) {
                try {
                    Iterator<Image> stream =
                            ClientCalls.blockingServerStreamingCall(
                                    channel, SCREENSHOT_STREAM, CallOptions.DEFAULT, request);
                    while (!stopRequested(stop) && stream.hasNext()) {
                        Frame frame = validate(stream.next(), previousSequence, !receivedAny);
                        receivedAny = true;
                        framesReceived++;
                        previousSequence = frame.sequence();
                        if (!frame.visible()) {
                            continue;
                        }
                        if (lastPublicationNs != 0
                                && frame.observedMonotonicNs() - lastPublicationNs
                                        < MIN_PUBLICATION_INTERVAL_NANOS) {
                            continue;
                        }
                        writeAtomically(outputRoot, "latest.frame", encode(frame));
                        lastPublicationNs = frame.observedMonotonicNs();
                        framesPublished++;
                        if (framesPublished == 1) {
                            writeAtomically(
                                    outputRoot,
                                    "ready",
                                    ("ready seq=" + frame.sequence() + "\n")
                                            .getBytes(StandardCharsets.US_ASCII));
                        }
                    }
                    if (!stopRequested(stop)) {
                        throw new IllegalStateException("emulator screenshot stream ended");
                    }
                } catch (StatusRuntimeException error) {
                    if (stopRequested(stop)) {
                        break;
                    }
                    if (!receivedAny
                            && error.getStatus().getCode() == Status.Code.UNAVAILABLE
                            && System.nanoTime() < startupDeadline) {
                        sleepBeforeRetry(stop);
                        continue;
                    }
                    throw error;
                }
            }
        } finally {
            channel.shutdownNow();
            try {
                if (!channel.awaitTermination(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("gRPC channel did not terminate");
                }
            } finally {
                stopWatcher.shutdownNow();
                if (!stopWatcher.awaitTermination(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("stop watcher did not terminate");
                }
            }
        }
        if (!receivedAny || framesPublished == 0) {
            throw new IllegalStateException("observer stopped before receiving a frame");
        }
        writeAtomically(
                outputRoot,
                "stopped",
                ("stopped frames_received="
                                + framesReceived
                                + " frames_published="
                                + framesPublished
                                + " last_seq="
                                + previousSequence
                                + "\n")
                        .getBytes(StandardCharsets.US_ASCII));
        System.out.printf(
                "ANDROID_EMULATOR_FRAME_OBSERVER=pass endpoint=127.0.0.1:8554 "
                        + "transport=grpc-stream format=rgb888 orientation=bottom-up "
                        + "frames_received=%d frames_published=%d last_seq=%d cleanup=joined%n",
                framesReceived, framesPublished, previousSequence);
        return 0;
    }

    private static int selfTest() throws Exception {
        Path root = Files.createTempDirectory("android-frame-observer-");
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
        int scenarios = 0;
        try {
            ImageFormat format =
                    ImageFormat.newBuilder()
                            .setFormat(ImageFormat.ImgFormat.RGB888)
                            .setWidth(120)
                            .setHeight(200)
                            .build();
            byte[] pixels = new byte[120 * 200 * 3];
            Image valid =
                    Image.newBuilder()
                            .setFormat(format)
                            .setImage(ByteString.copyFrom(pixels))
                            .setSeq(7)
                            .setTimestampUs(System.currentTimeMillis() * 1_000L)
                            .build();
            Frame frame = validate(valid, 6, false);
            writeAtomically(root, "latest.frame", encode(frame));
            byte[] encoded = Files.readAllBytes(root.resolve("latest.frame"));
            if (!new String(encoded, 0, "RUSTDESK_ANDROID_FRAME_V1\n".length(),
                            StandardCharsets.US_ASCII)
                    .equals("RUSTDESK_ANDROID_FRAME_V1\n")) {
                throw new AssertionError("atomic frame record magic differs");
            }
            scenarios++;
            try {
                validate(valid, 7, false);
                throw new AssertionError("duplicate sequence was accepted");
            } catch (IllegalArgumentException expected) {
                scenarios++;
            }
            try {
                validate(
                        valid.toBuilder().setImage(ByteString.copyFrom(new byte[3])).build(),
                        6,
                        false);
                throw new AssertionError("truncated frame was accepted");
            } catch (IllegalArgumentException expected) {
                scenarios++;
            }
            try {
                validate(
                        valid.toBuilder()
                                .setFormat(
                                        format.toBuilder()
                                                .setFormat(ImageFormat.ImgFormat.RGBA8888))
                                .build(),
                        6,
                        false);
                throw new AssertionError("wrong pixel format was accepted");
            } catch (IllegalArgumentException expected) {
                scenarios++;
            }
            try {
                validate(valid.toBuilder().setTimestampUs(0).build(), 6, false);
                throw new AssertionError("missing timestamp was accepted");
            } catch (IllegalArgumentException expected) {
                scenarios++;
            }
            Frame empty =
                    validate(
                            valid.toBuilder()
                                    .setFormat(format.toBuilder().setWidth(0).setHeight(0))
                                    .setImage(ByteString.EMPTY)
                                    .setSeq(8)
                                    .build(),
                            7,
                            false);
            if (empty.visible() || empty.pixels().length != 0) {
                throw new AssertionError("documented inactive-display frame was not retained empty");
            }
            scenarios++;
            try {
                validate(
                        valid.toBuilder()
                                .setFormat(format.toBuilder().setWidth(0).setHeight(200))
                                .setImage(ByteString.EMPTY)
                                .setSeq(8)
                                .build(),
                        7,
                        false);
                throw new AssertionError("partially empty dimensions were accepted");
            } catch (IllegalArgumentException expected) {
                scenarios++;
            }
        } finally {
            Files.deleteIfExists(root.resolve("latest.frame"));
            Files.deleteIfExists(root);
        }
        System.out.printf(
                "ANDROID_EMULATOR_FRAME_OBSERVER_SELF_TEST=pass scenarios=%d%n", scenarios);
        return 0;
    }

    private static void writeFailure(Path root, Throwable error) {
        try {
            String detail = error.getClass().getSimpleName() + ": " + error.getMessage();
            detail = detail.replace('\n', ' ').replace('\r', ' ');
            if (detail.length() > 512) {
                detail = detail.substring(0, 512);
            }
            writeAtomically(
                    root,
                    "failure",
                    ("failure=" + detail + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // The original error remains authoritative and is printed below.
        }
    }

    public static void main(String[] arguments) {
        try {
            if (arguments.length == 1 && arguments[0].equals("--self-test")) {
                System.exit(selfTest());
            }
            if (arguments.length != 3
                    || !arguments[0].equals(HOST)
                    || Integer.parseInt(arguments[1]) != PORT) {
                throw new IllegalArgumentException(
                        "usage: AndroidEmulatorFrameObserver 127.0.0.1 8554 OUTPUT_ROOT");
            }
            Path outputRoot = Path.of(arguments[2]).toRealPath(LinkOption.NOFOLLOW_LINKS);
            System.exit(observe(outputRoot));
        } catch (Throwable error) {
            if (arguments.length == 3) {
                try {
                    Path root = Path.of(arguments[2]).toRealPath(LinkOption.NOFOLLOW_LINKS);
                    writeFailure(root, error);
                } catch (IOException ignored) {
                    // The original error remains authoritative and is printed below.
                }
            }
            System.err.println("Android emulator frame observer: " + error);
            System.exit(1);
        }
    }
}
