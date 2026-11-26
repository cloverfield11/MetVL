use crate::HleModule;

pub fn wait_for_previous() {}

pub(crate) fn module() -> HleModule {
    HleModule {
        name: "lifecycle",
        dlls: &[
            "api-ms-win-core-psm-appnotify-*",
            "ext-ms-win-rtcore-ntuser-window-*",
        ],
        exports: vec![],
    }
}
