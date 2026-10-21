use super::*;
use scrap::codec::{Quality, BR_BALANCED, BR_BEST, BR_SPEED};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/*
FPS adjust:
a. new user connected =>set to INIT_FPS
b. TestDelay receive => update user's fps according to network delay
    When network delay < DELAY_THRESHOLD_150MS, set minimum fps according to image quality, and increase fps;
    When network delay >= DELAY_THRESHOLD_150MS, set minimum fps according to image quality, and decrease fps;
c. second timeout / TestDelay receive => update real fps to the minimum fps from all users

ratio adjust:
a. user set image quality => update to the maximum ratio of the latest quality
b. 3 seconds timeout => update ratio according to network delay
    When network delay < DELAY_THRESHOLD_150MS, increase ratio, max 150kbps;
    When network delay >= DELAY_THRESHOLD_150MS, decrease ratio;

adjust between FPS and ratio:
    When network delay < DELAY_THRESHOLD_150MS, fps is always higher than the minimum fps, and ratio is increasing;
    When network delay >= DELAY_THRESHOLD_150MS, fps is always lower than the minimum fps, and ratio is decreasing;

delay:
    use delay minus RTT as the actual network delay
*/

// Constants
pub const FPS: u32 = 30;
pub const MIN_FPS: u32 = 1;
pub const MAX_FPS: u32 = 120;
pub const INIT_FPS: u32 = 15;

// Bitrate ratio constants for different quality levels
const BR_MAX: f32 = 40.0; // 2000 * 2 / 100
const BR_MIN: f32 = 0.2;
const BR_MIN_HIGH_RESOLUTION: f32 = 0.1; // For high resolution, BR_MIN is still too high, so we set a lower limit
const MAX_BR_MULTIPLE: f32 = 1.0;

const HISTORY_DELAY_LEN: usize = 2;
const ADJUST_RATIO_INTERVAL: usize = 3; // Adjust quality ratio every 3 seconds
const DYNAMIC_SCREEN_THRESHOLD: usize = 2; // Allow increase quality ratio if encode more than 2 times in one second
const DELAY_THRESHOLD_150MS: u32 = 150; // 150ms is the threshold for good network condition

#[derive(Default, Debug, Clone)]
struct UserDelay {
    pending_delay: Option<u32>,
    delay_history: VecDeque<u32>,
    fps: Option<u32>,
    rtt_calculator: RttCalculator,
    quick_increase_fps_count: usize,
    increase_fps_count: usize,
}

impl UserDelay {
    fn add_delay(&mut self, delay: u32) {
        self.rtt_calculator.update(delay);
        if self.delay_history.len() >= HISTORY_DELAY_LEN {
            self.delay_history.pop_front();
        }
        self.delay_history.push_back(delay);
    }

    // Completed delay average or outstanding-probe age, minus RTT.
    fn avg_delay(&self) -> u32 {
        let len = self.delay_history.len();
        let measured_delay = if len > 0 {
            let total: u64 = self.delay_history.iter().map(|&delay| u64::from(delay)).sum();
            (total / len as u64) as u32
        } else {
            DELAY_THRESHOLD_150MS
        };
        let delay = measured_delay.max(self.pending_delay.unwrap_or_default());
        if let Some(rtt) = self.rtt_calculator.get_rtt() {
            delay.saturating_sub(rtt)
        } else {
            delay
        }
    }
}

// User session data structure
#[derive(Default, Debug, Clone)]
struct UserData {
    auto_adjust_fps: Option<u32>, // reserve for compatibility
    custom_fps: Option<u32>,
    delay: UserDelay,
    record: bool,
}

impl UserData {
    fn requested_fps(&self) -> u32 {
        let mut fps = self.custom_fps.unwrap_or(FPS);
        if let Some(auto_adjust_fps) = self.auto_adjust_fps {
            if fps == 0 || auto_adjust_fps < fps {
                fps = auto_adjust_fps;
            }
        }
        fps
    }
}

#[derive(Default, Debug, Clone)]
struct DisplayData {
    send_counter: usize, // Number of times encode during period
    support_changing_quality: bool,
}

// Main QoS controller structure
pub struct VideoQoS {
    fps: u32,
    ratio: f32,
    users: HashMap<i32, UserData>,
    // One current choice per live viewer, ordered by its latest request.
    qualities: Vec<(i32, Quality)>,
    displays: HashMap<String, DisplayData>,
    bitrate_store: u32,
    adjust_ratio_instant: Instant,
    abr_config: bool,
    new_user_instant: Instant,
}

impl Default for VideoQoS {
    fn default() -> Self {
        VideoQoS {
            fps: FPS,
            ratio: BR_BALANCED,
            users: Default::default(),
            qualities: Default::default(),
            displays: Default::default(),
            bitrate_store: 0,
            adjust_ratio_instant: Instant::now(),
            abr_config: true,
            new_user_instant: Instant::now(),
        }
    }
}

// Basic functionality
impl VideoQoS {
    // Calculate seconds per frame based on current FPS
    pub fn spf(&self) -> Duration {
        Duration::from_secs_f32(1. / (self.fps() as f32))
    }

    // Get current FPS within valid range
    pub fn fps(&self) -> u32 {
        let fps = self.fps;
        if fps >= MIN_FPS && fps <= MAX_FPS {
            fps
        } else {
            FPS
        }
    }

    // Store bitrate for later use
    pub fn store_bitrate(&mut self, bitrate: u32) {
        self.bitrate_store = bitrate;
    }

    // Get stored bitrate
    pub fn bitrate(&self) -> u32 {
        self.bitrate_store
    }

    // Get current bitrate ratio with bounds checking
    pub fn ratio(&mut self) -> f32 {
        if self.ratio < BR_MIN_HIGH_RESOLUTION || self.ratio > BR_MAX {
            self.ratio = BR_BALANCED;
        }
        self.ratio
    }

    // Check if any user is in recording mode
    pub fn record(&self) -> bool {
        self.users.iter().any(|u| u.1.record)
    }

    pub fn set_support_changing_quality(&mut self, video_service_name: &str, support: bool) {
        if let Some(display) = self.displays.get_mut(video_service_name) {
            display.support_changing_quality = support;
        }
    }

    // Check if variable bitrate encoding is supported and enabled
    pub fn in_vbr_state(&self) -> bool {
        self.abr_config && self.displays.iter().all(|e| e.1.support_changing_quality)
    }
}

// User session management
impl VideoQoS {
    // Initialize new user session
    pub fn on_connection_open(&mut self, id: i32) {
        self.users.insert(id, UserData::default());
        self.retire_quality(id);
        self.abr_config = Config::get_option("enable-abr") != "N";
        self.new_user_instant = Instant::now();
        self.adjust_fps();
    }

    // Clean up user session
    pub fn on_connection_close(&mut self, id: i32) {
        self.users.remove(&id);
        self.retire_quality(id);
        if self.users.is_empty() {
            *self = Default::default();
        } else {
            self.adjust_fps();
        }
    }

    fn retire_quality(&mut self, id: i32) {
        let previous = self.latest_quality();
        self.qualities.retain(|(owner, _)| *owner != id);
        let current = self.latest_quality();
        if current != previous {
            self.ratio = current.ratio();
        }
    }

    pub fn user_custom_fps(&mut self, id: i32, fps: u32) {
        if fps < MIN_FPS || fps > MAX_FPS {
            return;
        }
        if let Some(user) = self.users.get_mut(&id) {
            user.custom_fps = Some(fps);
            self.adjust_fps();
        }
    }

    pub fn user_auto_adjust_fps(&mut self, id: i32, fps: u32) {
        if fps < MIN_FPS || fps > MAX_FPS {
            return;
        }
        if let Some(user) = self.users.get_mut(&id) {
            user.auto_adjust_fps = Some(fps);
            self.adjust_fps();
        }
    }

    pub fn user_image_quality(&mut self, id: i32, image_quality: i32) {
        let convert_quality = |q: i32| -> Quality {
            if q == ImageQuality::Balanced.value() {
                Quality::Balanced
            } else if q == ImageQuality::Low.value() {
                Quality::Low
            } else if q == ImageQuality::Best.value() {
                Quality::Best
            } else {
                let b = ((q >> 8 & 0xFFF) * 2) as f32 / 100.0;
                Quality::Custom(b.clamp(BR_MIN, BR_MAX))
            }
        };

        if self.users.contains_key(&id) {
            let quality = convert_quality(image_quality);
            self.qualities.retain(|(owner, _)| *owner != id);
            self.qualities.push((id, quality));
            self.ratio = quality.ratio();
        }
    }

    pub fn user_record(&mut self, id: i32, v: bool) {
        if let Some(user) = self.users.get_mut(&id) {
            user.record = v;
        }
    }

    pub fn user_network_delay(&mut self, id: i32, delay: u32) {
        let sending_fps = self.fps.min(self.highest_fps());
        let target_ratio = self.latest_quality().ratio();

        // For bad network, small fps means quick reaction and high quality
        let (min_fps, normal_fps) = if target_ratio >= BR_BEST {
            (8, 16)
        } else if target_ratio >= BR_BALANCED {
            (10, 20)
        } else {
            (12, 24)
        };

        // Calculate minimum acceptable delay-fps product
        let dividend_ms = DELAY_THRESHOLD_150MS * min_fps;

        let mut adjust_ratio = false;
        if let Some(user) = self.users.get_mut(&id) {
            let highest_fps = user.requested_fps().clamp(MIN_FPS, MAX_FPS);
            let delay = delay.max(10);
            let old_avg_delay = user.delay.avg_delay();
            user.delay.pending_delay = None;
            user.delay.add_delay(delay);
            let mut avg_delay = user.delay.avg_delay();
            avg_delay = avg_delay.max(10);
            let previous_fps = user.delay.fps.unwrap_or(INIT_FPS);
            let mut fps = previous_fps;

            // Adaptive FPS adjustment based on network delay:
            if avg_delay < 50 {
                user.delay.quick_increase_fps_count += 1;
                let mut step = if fps < normal_fps { 1 } else { 0 };
                if user.delay.quick_increase_fps_count >= 3 {
                    // After 3 consecutive good samples, increase more aggressively
                    user.delay.quick_increase_fps_count = 0;
                    step = 5;
                }
                fps = min_fps.max(fps + step);
            } else if avg_delay < 100 {
                let step = if avg_delay < old_avg_delay {
                    if fps < normal_fps {
                        1
                    } else {
                        0
                    }
                } else {
                    0
                };
                fps = min_fps.max(fps + step);
            } else if avg_delay < DELAY_THRESHOLD_150MS {
                fps = min_fps.max(fps);
            } else {
                let devide_fps = ((fps as f32) / (avg_delay as f32 / DELAY_THRESHOLD_150MS as f32))
                    .ceil() as u32;
                if avg_delay < 200 {
                    fps = min_fps.max(devide_fps);
                } else if avg_delay < 300 {
                    fps = min_fps.min(devide_fps);
                } else if avg_delay < 600 {
                    fps = dividend_ms / avg_delay;
                } else {
                    fps = (dividend_ms / avg_delay).min(devide_fps);
                }
            }

            if avg_delay < DELAY_THRESHOLD_150MS {
                user.delay.increase_fps_count += 1;
            } else {
                user.delay.increase_fps_count = 0;
            }
            if user.delay.increase_fps_count >= 3 {
                // After 3 stable samples, try increasing FPS
                user.delay.increase_fps_count = 0;
                fps += 1;
            }

            // Reset quick increase counter if network condition worsens
            if avg_delay >= 50 {
                user.delay.quick_increase_fps_count = 0;
            }

            fps = fps.clamp(MIN_FPS, highest_fps);
            // A limited shared stream cannot probe an increase in this user's rate.
            if sending_fps < previous_fps {
                fps = fps.min(previous_fps);
            }
            // first network delay message
            adjust_ratio = user.delay.fps.is_none();
            user.delay.fps = Some(fps);
        }
        self.adjust_fps();
        if adjust_ratio && !cfg!(target_os = "linux") {
            //Reduce the possibility of vaapi being created twice
            self.adjust_ratio(false);
        }
    }

    pub fn user_delay_response_elapsed(&mut self, id: i32, elapsed: u128) {
        if let Some(user) = self.users.get_mut(&id) {
            user.delay.pending_delay = (elapsed > 2000)
                .then(|| elapsed.min(u32::MAX as u128) as u32);
            self.adjust_fps();
        }
    }
}

// Common adjust functions
impl VideoQoS {
    pub fn new_display(&mut self, video_service_name: String) {
        self.displays
            .insert(video_service_name, DisplayData::default());
    }

    pub fn remove_display(&mut self, video_service_name: &str) {
        self.displays.remove(video_service_name);
    }

    pub fn update_display_data(&mut self, video_service_name: &str, send_counter: usize) {
        if let Some(display) = self.displays.get_mut(video_service_name) {
            display.send_counter += send_counter;
        }
        self.adjust_fps();
        let abr_enabled = self.in_vbr_state();
        if abr_enabled {
            if self.adjust_ratio_instant.elapsed().as_secs() >= ADJUST_RATIO_INTERVAL as u64 {
                let dynamic_screen = self
                    .displays
                    .iter()
                    .any(|d| d.1.send_counter >= ADJUST_RATIO_INTERVAL * DYNAMIC_SCREEN_THRESHOLD);
                self.displays.iter_mut().for_each(|d| {
                    d.1.send_counter = 0;
                });
                self.adjust_ratio(dynamic_screen);
            }
        } else {
            self.ratio = self.latest_quality().ratio();
        }
    }

    #[inline]
    fn highest_fps(&self) -> u32 {
        let fps = self
            .users
            .values()
            .map(UserData::requested_fps)
            .filter(|u| *u >= MIN_FPS)
            .min()
            .unwrap_or(FPS);

        fps.clamp(MIN_FPS, MAX_FPS)
    }

    // Get latest quality settings from all users
    pub fn latest_quality(&self) -> Quality {
        self.qualities
            .last()
            .map(|(_, quality)| *quality)
            .unwrap_or_default()
    }

    // Adjust quality ratio based on network delay and screen changes
    fn adjust_ratio(&mut self, dynamic_screen: bool) {
        if !self.in_vbr_state() {
            return;
        }
        // Get maximum delay from all users
        let max_delay = self.users.iter().map(|u| u.1.delay.avg_delay()).max();
        let Some(max_delay) = max_delay else {
            return;
        };

        let target_quality = self.latest_quality();
        let target_ratio = self.latest_quality().ratio();
        let current_ratio = self.ratio;
        let current_bitrate = self.bitrate();

        // Calculate minimum ratio for high resolution (1Mbps baseline)
        let ratio_1mbps = if current_bitrate > 0 {
            Some((current_ratio * 1000.0 / current_bitrate as f32).max(BR_MIN_HIGH_RESOLUTION))
        } else {
            None
        };

        // Calculate ratio for adding 150kbps bandwidth
        let ratio_add_150kbps = if current_bitrate > 0 {
            Some((current_bitrate + 150) as f32 * current_ratio / current_bitrate as f32)
        } else {
            None
        };

        // Set minimum ratio based on quality mode
        let min = match target_quality {
            Quality::Best => {
                // For Best quality, ensure minimum 1Mbps for high resolution
                let mut min = BR_BEST / 2.5;
                if let Some(ratio_1mbps) = ratio_1mbps {
                    if min > ratio_1mbps {
                        min = ratio_1mbps;
                    }
                }
                min.max(BR_MIN)
            }
            Quality::Balanced => {
                let mut min = (BR_BALANCED / 2.0).min(0.4);
                if let Some(ratio_1mbps) = ratio_1mbps {
                    if min > ratio_1mbps {
                        min = ratio_1mbps;
                    }
                }
                min.max(BR_MIN_HIGH_RESOLUTION)
            }
            Quality::Low => BR_MIN_HIGH_RESOLUTION,
            Quality::Custom(_) => BR_MIN_HIGH_RESOLUTION,
        };
        let max = target_ratio * MAX_BR_MULTIPLE;

        let mut v = current_ratio;

        // Adjust ratio based on network delay thresholds
        if max_delay < 50 {
            if dynamic_screen {
                v = current_ratio * 1.15;
            }
        } else if max_delay < 100 {
            if dynamic_screen {
                v = current_ratio * 1.1;
            }
        } else if max_delay < DELAY_THRESHOLD_150MS {
            if dynamic_screen {
                v = current_ratio * 1.05;
            }
        } else if max_delay < 200 {
            v = current_ratio * 0.95;
        } else if max_delay < 300 {
            v = current_ratio * 0.9;
        } else if max_delay < 500 {
            v = current_ratio * 0.85;
        } else {
            v = current_ratio * 0.8;
        }

        // Limit quality increase rate for better stability
        if let Some(ratio_add_150kbps) = ratio_add_150kbps {
            if v > ratio_add_150kbps
                && ratio_add_150kbps > current_ratio
                && current_ratio >= BR_SPEED
            {
                v = ratio_add_150kbps;
            }
        }

        self.ratio = v.clamp(min, max);
        self.adjust_ratio_instant = Instant::now();
    }

    // Adjust fps based on network delay and user response time
    fn adjust_fps(&mut self) {
        let highest_fps = self.highest_fps();
        // Get minimum fps from all users
        let mut fps = self
            .users
            .iter()
            .map(|u| u.1.delay.fps.unwrap_or(INIT_FPS))
            .min()
            .unwrap_or(INIT_FPS);

        if self.users.iter().any(|u| u.1.delay.pending_delay.is_some()) {
            if fps > MIN_FPS + 1 {
                fps = MIN_FPS + 1;
            }
        }

        // For new connections (within 1 second), cap fps to INIT_FPS to ensure stability
        if self.new_user_instant.elapsed().as_secs() < 1 {
            if fps > INIT_FPS {
                fps = INIT_FPS;
            }
        }

        // Ensure fps stays within valid range
        self.fps = fps.clamp(MIN_FPS, highest_fps);
    }
}

#[derive(Default, Debug, Clone)]
struct RttCalculator {
    min_rtt: Option<u32>,        // Historical minimum RTT ever observed
    window_min_rtt: Option<u32>, // Minimum RTT within last 60 samples
    smoothed_rtt: Option<u32>,   // Smoothed RTT estimation
    samples: VecDeque<u32>,      // Last 60 RTT samples
}

impl RttCalculator {
    const WINDOW_SAMPLES: usize = 60; // Keep last 60 samples
    const MIN_SAMPLES: usize = 10; // Require at least 10 samples
    const ALPHA: f32 = 0.5; // Smoothing factor for weighted average

    /// Update RTT estimates with a new sample
    pub fn update(&mut self, delay: u32) {
        // 1. Update historical minimum RTT
        match self.min_rtt {
            Some(min_rtt) if delay < min_rtt => self.min_rtt = Some(delay),
            None => self.min_rtt = Some(delay),
            _ => {}
        }

        // 2. Update sample window
        if self.samples.len() >= Self::WINDOW_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(delay);

        // 3. Calculate minimum RTT within the window
        self.window_min_rtt = self.samples.iter().min().copied();

        // 4. Calculate smoothed RTT
        // Use weighted average if we have enough samples
        if self.samples.len() >= Self::WINDOW_SAMPLES {
            if let (Some(min), Some(window_min)) = (self.min_rtt, self.window_min_rtt) {
                // Weighted average of historical minimum and window minimum
                let new_srtt =
                    ((1.0 - Self::ALPHA) * min as f32 + Self::ALPHA * window_min as f32) as u32;
                self.smoothed_rtt = Some(new_srtt);
            }
        }
    }

    /// Get current RTT estimate
    /// Returns None if no valid estimation is available
    pub fn get_rtt(&self) -> Option<u32> {
        if let Some(rtt) = self.smoothed_rtt {
            return Some(rtt);
        }
        if self.samples.len() >= Self::MIN_SAMPLES {
            if let Some(rtt) = self.min_rtt {
                return Some(rtt);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_controller() -> VideoQoS {
        let mut qos = VideoQoS::default();
        qos.on_connection_open(7);
        qos.new_user_instant = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        for _ in 0..60 {
            qos.user_network_delay(7, 20);
        }
        assert_eq!(qos.fps(), FPS);
        qos
    }

    fn healthy_pair() -> VideoQoS {
        let mut qos = healthy_controller();
        qos.on_connection_open(8);
        qos.new_user_instant = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        for _ in 0..60 {
            qos.user_network_delay(7, 20);
            qos.user_network_delay(8, 20);
        }
        assert_eq!(qos.fps(), FPS);
        assert_eq!(qos.users[&8].delay.fps, Some(FPS));
        qos
    }

    #[test]
    fn quality_requests_in_one_clock_tick_follow_request_order() {
        let mut qos = healthy_pair();
        for _ in 0..1024 {
            let tick = hbb_common::get_time();
            qos.user_image_quality(7, ImageQuality::Low.value());
            qos.user_image_quality(8, ImageQuality::Best.value());
            let forward = qos.latest_quality() == Quality::Best && qos.ratio() == BR_BEST;
            qos.user_image_quality(8, ImageQuality::Low.value());
            qos.user_image_quality(7, ImageQuality::Best.value());
            let reverse = qos.latest_quality() == Quality::Best && qos.ratio() == BR_BEST;
            if hbb_common::get_time() == tick {
                println!("VIDEO_QOS_QUALITY_ORDER=observed same_tick=true forward={forward} reverse={reverse}");
                assert!(forward && reverse, "latest request must win in either viewer order");
                return;
            }
        }
        panic!("could not observe four quality requests in one millisecond");
    }

    #[test]
    fn closing_quality_requester_restores_latest_live_choice() {
        let mut qos = healthy_pair();
        qos.on_connection_open(9);
        qos.user_image_quality(7, ImageQuality::Low.value());
        qos.user_image_quality(8, ImageQuality::Balanced.value());
        qos.user_image_quality(9, ImageQuality::Best.value());
        qos.user_image_quality(8, ImageQuality::Low.value());
        let updated = qos.latest_quality() == Quality::Low && qos.ratio() == BR_SPEED;
        qos.on_connection_close(8);
        let previous = qos.latest_quality() == Quality::Best && qos.ratio() == BR_BEST;
        qos.on_connection_close(9);
        let oldest = qos.latest_quality() == Quality::Low && qos.ratio() == BR_SPEED;
        qos.on_connection_close(7);
        let reset = qos.latest_quality() == Quality::Balanced && qos.ratio() == BR_BALANCED;
        println!("VIDEO_QOS_QUALITY_RETIRE=observed updated={updated} previous={previous} oldest={oldest} reset={reset}");
        assert!(updated && previous && oldest && reset);
    }

    #[test]
    fn quality_requests_require_a_live_viewer_and_retire_on_replacement() {
        let mut qos = healthy_controller();
        qos.user_image_quality(7, ImageQuality::Best.value());
        qos.user_image_quality(999, ImageQuality::Low.value());
        let unknown_refused = qos.latest_quality() == Quality::Best && qos.ratio() == BR_BEST;
        qos.on_connection_open(8);
        let unconfigured_preserved = qos.latest_quality() == Quality::Best && qos.ratio() == BR_BEST;
        qos.on_connection_open(7);
        let replacement_retired = qos.latest_quality() == Quality::Balanced && qos.ratio() == BR_BALANCED;
        qos.user_image_quality(8, 75 << 8);
        let custom_preserved = qos.latest_quality() == Quality::Custom(1.5);
        qos.on_connection_close(8);
        let live_default = qos.latest_quality() == Quality::Balanced && qos.ratio() == BR_BALANCED;
        println!("VIDEO_QOS_QUALITY_OWNER=observed unknown_refused={unknown_refused} unconfigured_preserved={unconfigured_preserved} replacement_retired={replacement_retired} custom_preserved={custom_preserved} live_default={live_default}");
        assert!(unknown_refused && unconfigured_preserved && replacement_retired
            && custom_preserved && live_default);
    }

    #[test]
    fn quality_retirement_preserves_adaptation_when_target_unchanged() {
        let mut cases = 0;
        for quality in [ImageQuality::Best.value(), ImageQuality::Balanced.value(), ImageQuality::Low.value(), 75 << 8] {
            for replacement in [false, true] {
                for id in [7, 8, 999] {
                    let mut qos = healthy_pair();
                    qos.new_display("quality-continuity".into());
                    qos.set_support_changing_quality("quality-continuity", true);
                    qos.user_image_quality(7, quality);
                    qos.user_image_quality(8, quality);
                    let target = qos.latest_quality();
                    qos.user_delay_response_elapsed(7, 4000);
                    qos.adjust_ratio(true);
                    let adapted = qos.ratio();
                    assert!(adapted < target.ratio(), "actual congestion adjustment must run");
                    if replacement { qos.on_connection_open(id); }
                    else { qos.on_connection_close(id); }
                    assert_eq!(qos.latest_quality(), target);
                    assert_eq!(qos.ratio(), adapted,
                        "unchanged quality must retain congestion adaptation: quality={quality} replacement={replacement} id={id}");
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 24);
        println!("VIDEO_QOS_QUALITY_CONTINUITY=observed cases={cases} preserved=true");
    }

    #[test]
    fn pending_peer_does_not_reduce_healthy_peer_estimate() {
        let mut qos = healthy_pair();
        qos.user_delay_response_elapsed(7, 4000);
        assert_eq!(qos.fps(), MIN_FPS + 1);
        for _ in 0..60 {
            qos.user_network_delay(8, 20);
            assert_eq!(qos.fps(), MIN_FPS + 1,
                "the shared stream must retain pending-peer congestion control");
        }
        assert_eq!(qos.users[&8].delay.fps, Some(FPS),
            "a healthy peer's estimate must not inherit another peer's pending cap");
        qos.on_connection_close(7);
        assert_eq!(qos.fps(), FPS);
        assert_eq!(qos.users.len(), 1);
    }

    #[test]
    fn opening_a_viewer_recalculates_rate_from_current_owners() {
        let mut outcomes = Vec::new();
        for replacement in [false, true] {
            for (prior, limited, pending, new_fps, replacement_fps) in [
                ("healthy", None, None, INIT_FPS, INIT_FPS),
                ("limited-owner", Some(7), None, 5, INIT_FPS),
                ("pending-owner", None, Some(7), MIN_FPS + 1, INIT_FPS),
                ("limited-other", Some(8), None, 5, 5),
                ("pending-other", None, Some(8), MIN_FPS + 1, MIN_FPS + 1),
            ] {
                let mut qos = healthy_pair();
                if let Some(id) = limited {
                    qos.user_custom_fps(id, 5);
                    qos.user_network_delay(id, 20);
                }
                if let Some(id) = pending {
                    qos.user_delay_response_elapsed(id, 4000);
                }
                let other = qos.users[&8].clone();
                let id = if replacement { 7 } else { 9 };
                qos.on_connection_open(id);
                let user = &qos.users[&id];
                let fresh_owner = user.custom_fps.is_none() && user.auto_adjust_fps.is_none()
                    && user.delay.fps.is_none() && user.delay.pending_delay.is_none()
                    && user.delay.delay_history.is_empty() && user.delay.rtt_calculator.samples.is_empty();
                let current = &qos.users[&8];
                let other_preserved = current.custom_fps == other.custom_fps
                    && current.delay.fps == other.delay.fps
                    && current.delay.pending_delay == other.delay.pending_delay
                    && current.delay.delay_history == other.delay.delay_history
                    && current.delay.rtt_calculator.samples == other.delay.rtt_calculator.samples;
                let expected = if replacement { replacement_fps } else { new_fps };
                let actual = qos.fps();
                println!("VIDEO_QOS_RATE_ADMISSION=observed replacement={replacement} prior={prior} expected_fps={expected} actual_fps={actual} fresh_owner={fresh_owner} other_preserved={other_preserved}");
                outcomes.push(actual == expected && fresh_owner && other_preserved
                    && qos.users.len() == if replacement { 2 } else { 3 });
            }
        }
        assert_eq!(outcomes.len(), 10);
        assert!(outcomes.into_iter().all(|ok| ok),
            "admission must immediately derive the shared rate from the fresh and retained owners");
    }

    #[test]
    fn peer_fps_limits_do_not_reduce_other_peers_estimates() {
        let mut immediate = Vec::new();
        for automatic in [false, true] {
            let mut qos = healthy_pair();
            if automatic {
                qos.user_auto_adjust_fps(7, 5);
            } else {
                qos.user_custom_fps(7, 5);
            }
            let actual = qos.fps();
            let requested = qos.users[&7].requested_fps();
            let other_estimate = qos.users[&8].delay.fps;
            println!("VIDEO_QOS_RATE_LIMIT=observed automatic={automatic} expected_fps=5 actual_fps={actual} requested_fps={requested} other_estimate={other_estimate:?}");
            immediate.push(actual == 5 && requested == 5 && other_estimate == Some(FPS));
            for _ in 0..60 {
                qos.user_network_delay(7, 20);
                qos.user_network_delay(8, 20);
                assert_eq!(qos.fps(), 5,
                    "the shared stream must honor the remaining peer's requested limit");
            }
            assert_eq!(qos.users[&7].delay.fps, Some(5));
            assert_eq!(qos.users[&8].delay.fps, Some(FPS),
                "a peer's requested limit must not become another peer's estimate");
            qos.on_connection_close(7);
            assert_eq!(qos.fps(), FPS);
        }
        assert!(immediate.into_iter().all(|ok| ok),
            "an admitted viewer rate limit must take effect without another feedback or display update");
    }

    #[test]
    fn closing_pending_peer_recalculates_rate_without_another_frame() {
        let mut qos = healthy_pair();
        qos.user_custom_fps(8, 20);
        qos.user_delay_response_elapsed(7, 4000);
        assert_eq!(qos.fps(), MIN_FPS + 1);
        assert_eq!(qos.users[&8].delay.fps, Some(FPS));
        qos.on_connection_close(7);
        assert_eq!(qos.fps(), 20,
            "retirement must immediately derive the rate from the remaining live peers");
        assert_eq!(qos.users[&8].custom_fps, Some(20));
        assert_eq!(qos.users.len(), 1);
        qos.on_connection_close(8);
        assert!(qos.users.is_empty());
        assert_eq!(qos.fps(), FPS);
    }

    #[test]
    fn pending_probe_observation_preserves_completed_rtt_history() {
        let mut qos = healthy_controller();
        let samples = qos.users[&7].delay.rtt_calculator.samples.clone();
        let delays = qos.users[&7].delay.delay_history.clone();
        for elapsed in [2001, 3000, 5000] {
            qos.user_delay_response_elapsed(7, elapsed);
            assert_eq!(qos.fps(), MIN_FPS + 1);
        }
        assert_eq!(qos.users[&7].delay.rtt_calculator.samples, samples,
            "one unanswered probe cannot manufacture completed RTT measurements");
        assert_eq!(qos.users[&7].delay.delay_history, delays);
        assert!(qos.users[&7].delay.avg_delay() >= 4980);
    }

    #[test]
    fn completed_probe_reply_retires_pending_congestion() {
        let mut qos = healthy_controller();
        qos.user_delay_response_elapsed(7, 2500);
        assert!(qos.users[&7].delay.pending_delay.is_some());
        qos.user_network_delay(7, 2500);
        assert!(qos.users[&7].delay.pending_delay.is_none(),
            "an observed reply completes the pending probe immediately");
        assert_eq!(qos.users[&7].delay.delay_history.back(), Some(&2500));
        assert_eq!(qos.users[&7].delay.rtt_calculator.samples.back(), Some(&2500));
    }

    #[test]
    fn pending_probe_congestion_controls_rate_and_quality() {
        let mut qos = healthy_controller();
        qos.new_display("monitor".to_owned());
        qos.set_support_changing_quality("monitor", true);
        qos.store_bitrate(2000);
        qos.user_delay_response_elapsed(7, 2000);
        assert_eq!(qos.fps(), FPS);
        let ratio = qos.ratio();
        qos.user_delay_response_elapsed(7, 4000);
        assert_eq!(qos.fps(), MIN_FPS + 1);
        assert!(qos.users[&7].delay.avg_delay() >= DELAY_THRESHOLD_150MS);
        qos.adjust_ratio(true);
        assert!(qos.ratio() < ratio,
            "an unanswered probe must still lower the sending bitrate");
        qos.user_delay_response_elapsed(999, 4000);
        assert_eq!(qos.users.len(), 1);
        assert_eq!(qos.fps(), MIN_FPS + 1);
    }

    #[test]
    fn fresh_probes_after_outage_restore_rate_without_reopening_user() {
        let mut qos = healthy_controller();
        qos.user_custom_fps(7, 20);
        for _ in 0..3 {
            qos.user_delay_response_elapsed(7, 2500);
            assert_eq!(qos.fps(), MIN_FPS + 1);
            qos.user_network_delay(7, 2500);
            for _ in 0..60 {
                qos.user_delay_response_elapsed(7, 0);
                qos.user_network_delay(7, 20);
                assert!((MIN_FPS..=20).contains(&qos.fps()));
            }
            assert_eq!(qos.fps(), 20);
            assert_eq!(qos.users.len(), 1);
        }
        qos.on_connection_close(7);
        assert!(qos.users.is_empty());
        assert_eq!(qos.fps(), FPS);
    }

    #[test]
    fn shared_rate_limit_does_not_manufacture_higher_rate_estimates() {
        let mut qos = healthy_pair();
        qos.user_custom_fps(8, MAX_FPS);
        qos.user_custom_fps(7, 5);
        // A newly requested shared limit is effective before its owner's next reply.
        qos.user_network_delay(8, 20);
        for _ in 0..60 {
            qos.user_network_delay(7, 20);
            qos.user_network_delay(8, 20);
            assert_eq!(qos.fps(), 5);
        }
        assert_eq!(qos.users[&8].delay.fps, Some(FPS),
            "low delay at a restricted sending rate cannot prove higher capacity");
        qos.on_connection_close(7);
        assert_eq!(qos.fps(), FPS);
        for _ in 0..60 {
            qos.user_network_delay(8, 20);
        }
        assert_eq!(qos.fps(), MAX_FPS,
            "new feedback at the unrestricted rate must still allow adaptation");
        let mut outcomes = Vec::new();
        for (excess, expected_fps, expected_quick) in [(49, 36, 2), (50, 31, 1), (51, 31, 1)] {
            let mut qos = healthy_controller();
            qos.user_custom_fps(7, MAX_FPS);
            let mut observed_excess = 0;
            for delay in [20, 20, 20 + 2 * excess, 20, 20] {
                qos.user_network_delay(7, delay);
                observed_excess = observed_excess.max(qos.users[&7].delay.avg_delay());
            }
            let actual_fps = qos.fps();
            let actual_quick = qos.users[&7].delay.quick_increase_fps_count;
            println!("VIDEO_QOS_CONGESTION=observed kind=quick-boundary excess_ms={excess} observed_excess_ms={observed_excess} expected_fps={expected_fps} actual_fps={actual_fps} expected_quick={expected_quick} actual_quick={actual_quick}");
            outcomes.push(observed_excess == excess && actual_fps == expected_fps
                && actual_quick == expected_quick);
        }
        assert!(outcomes.into_iter().all(|ok| ok),
            "only consecutive delay samples below 50 ms may trigger rapid FPS probing");
    }

    fn controller_with_baseline(round_trip: u32) -> VideoQoS {
        let mut qos = VideoQoS::default();
        qos.on_connection_open(7);
        qos.new_user_instant = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        qos.new_display("monitor".to_owned());
        qos.set_support_changing_quality("monitor", true);
        qos.store_bitrate(2000);
        for _ in 0..120 {
            qos.user_network_delay(7, round_trip);
            qos.adjust_ratio(true);
        }
        qos
    }

    #[test]
    fn baseline_round_trip_is_not_congestion() {
        let mut outcomes = Vec::new();
        for round_trip in [150, 250, 1000] {
            let mut qos = controller_with_baseline(round_trip);
            let excess = qos.users[&7].delay.avg_delay();
            let fps = qos.fps();
            let quality_restored = qos.ratio() == qos.latest_quality().ratio();
            println!("VIDEO_QOS_BASE_RTT=observed rtt_ms={round_trip} excess_ms={excess} fps={fps} quality_restored={quality_restored}");
            outcomes.push(excess == 0 && fps == FPS && quality_restored);
        }
        assert!(outcomes.into_iter().all(|ok| ok),
            "completed delay equal to its learned baseline has no excess congestion");
    }

    #[test]
    fn baseline_round_trip_recovers_after_pending_outage() {
        let mut qos = controller_with_baseline(250);
        qos.user_custom_fps(7, 20);
        let mut outcomes = Vec::new();
        for cycle in 0..3 {
            qos.user_delay_response_elapsed(7, 4000);
            assert!((MIN_FPS..=MIN_FPS + 1).contains(&qos.fps()));
            qos.adjust_ratio(true);
            qos.user_network_delay(7, 4250);
            for _ in 0..120 {
                qos.user_network_delay(7, 250);
                qos.adjust_ratio(true);
            }
            let excess = qos.users[&7].delay.avg_delay();
            let fps = qos.fps();
            let quality_restored = qos.ratio() == qos.latest_quality().ratio();
            let pending_retired = qos.users[&7].delay.pending_delay.is_none();
            let owner_preserved = qos.users.len() == 1 && qos.users[&7].custom_fps == Some(20);
            println!("VIDEO_QOS_RECOVERY=observed cycle={cycle} excess_ms={excess} fps={fps} quality_restored={quality_restored} pending_retired={pending_retired} owner_preserved={owner_preserved}");
            outcomes.push(excess == 0 && fps == 20 && quality_restored
                && pending_retired && owner_preserved);
        }
        assert!(outcomes.into_iter().all(|ok| ok),
            "fresh feedback must restore the same viewer's rate and quality after each outage");
    }

    #[test]
    fn excess_delay_above_baseline_still_reduces_rate() {
        let mut qos = controller_with_baseline(250);
        let previous_fps = qos.fps();
        let previous_ratio = qos.ratio();
        for _ in 0..6 {
            qos.user_network_delay(7, 1500);
            qos.adjust_ratio(true);
        }
        let excess = qos.users[&7].delay.avg_delay();
        let rate_reduced = qos.fps() < previous_fps;
        let quality_not_increased = qos.ratio() <= previous_ratio;
        println!("VIDEO_QOS_CONGESTION=observed excess_ms={excess} rate_reduced={rate_reduced} quality_not_increased={quality_not_increased}");
        assert!(excess >= DELAY_THRESHOLD_150MS && rate_reduced && quality_not_increased);
    }

    #[test]
    fn two_fresh_replies_retire_a_completed_delay_spike() {
        let mut qos = healthy_controller();
        qos.user_custom_fps(7, 20);
        qos.user_network_delay(7, 2020);
        qos.user_network_delay(7, 20);
        assert!(qos.users[&7].delay.avg_delay() >= DELAY_THRESHOLD_150MS);
        qos.user_network_delay(7, 20);
        let excess = qos.users[&7].delay.avg_delay();
        let retained = qos.users[&7].delay.delay_history.len();
        let owner_preserved = qos.users.len() == 1 && qos.users[&7].custom_fps == Some(20);
        println!("VIDEO_QOS_DELAY_WINDOW=observed excess_ms={excess} retained={retained} fps={} owner_preserved={owner_preserved}", qos.fps());
        assert_eq!(excess, 0, "two fresh replies must retire the preceding spike");
        assert_eq!(retained, 2);
        assert!(qos.fps() >= 10 && owner_preserved);
    }

    #[test]
    fn delay_average_accepts_the_full_u32_measurement_domain() {
        let mut delay = UserDelay::default();
        delay.add_delay(u32::MAX);
        delay.add_delay(u32::MAX - 2);
        let average = delay.avg_delay();
        delay.pending_delay = Some(u32::MAX);
        let pending = delay.avg_delay();
        println!("VIDEO_QOS_DELAY_RANGE=observed average_ms={average} pending_ms={pending}");
        assert_eq!(average, u32::MAX - 1);
        assert_eq!(pending, u32::MAX);
    }

    #[test]
    fn large_completed_delays_recover_in_the_same_controller() {
        let mut qos = healthy_controller();
        qos.user_custom_fps(7, 20);
        qos.user_network_delay(7, u32::MAX);
        qos.user_network_delay(7, u32::MAX - 2);
        let excess = qos.users[&7].delay.avg_delay();
        assert!(excess >= DELAY_THRESHOLD_150MS && qos.fps() == MIN_FPS);
        qos.user_delay_response_elapsed(7, u128::MAX);
        let pending_excess = qos.users[&7].delay.avg_delay();
        assert!(pending_excess >= excess);
        qos.user_network_delay(7, 20);
        qos.user_network_delay(7, 20);
        let recovered = qos.users[&7].delay.avg_delay();
        let owner_preserved = qos.users.len() == 1 && qos.users[&7].custom_fps == Some(20)
            && qos.users[&7].delay.pending_delay.is_none();
        println!("VIDEO_QOS_DELAY_RECOVERY=observed excess_ms={excess} pending_excess_ms={pending_excess} recovered_ms={recovered} fps={} owner_preserved={owner_preserved}", qos.fps());
        assert_eq!(recovered, 0);
        assert!(qos.fps() >= 10 && owner_preserved);
    }

}
