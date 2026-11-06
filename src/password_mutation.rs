/// The observed outcome of one password change, including loss of confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordMutationOutcome {
    Applied,
    Denied,
    Failed,
    Uncertain,
}

impl PasswordMutationOutcome {
    pub(crate) fn into_result(self) -> hbb_common::ResultType<()> {
        match self {
            Self::Applied => Ok(()),
            Self::Denied => hbb_common::bail!("Password change was denied"),
            Self::Failed => hbb_common::bail!("Password change failed"),
            Self::Uncertain => hbb_common::bail!(
                "Password change outcome remains unknown; it may have been applied"
            ),
        }
    }
}
