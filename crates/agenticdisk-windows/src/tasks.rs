//! Scheduled tasks through the Task Scheduler COM API, which works without admin rights (the
//! `System32\Tasks` folder does not).

use windows::Win32::System::Com::*;
use windows::Win32::System::TaskScheduler::*;
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface};

pub struct Task {
    pub path: String,
    pub enabled: bool,
    pub author: String,
    /// (executable, arguments) for each exec action.
    pub actions: Vec<(String, String)>,
    /// The definition could not be read (usually needs admin): actions are unknown, not absent.
    pub unreadable: bool,
}

pub fn list() -> windows::core::Result<Vec<Task>> {
    // SAFETY: COM is initialized for this thread before any call; every interface is used only
    // on this thread and released by its Drop.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
        let empty = VARIANT::default();
        service.Connect(&empty, &empty, &empty, &empty)?;
        let root = service.GetFolder(&BSTR::from("\\"))?;
        let mut out = Vec::new();
        walk(&root, &mut out);
        Ok(out)
    }
}

unsafe fn walk(folder: &ITaskFolder, out: &mut Vec<Task>) {
    unsafe {
        if let Ok(tasks) = folder.GetTasks(TASK_ENUM_HIDDEN.0) {
            let count = tasks.Count().unwrap_or(0);
            for i in 1..=count {
                if let Ok(task) = tasks.get_Item(&VARIANT::from(i)) {
                    out.push(read(&task));
                }
            }
        }
        if let Ok(folders) = folder.GetFolders(0) {
            let count = folders.Count().unwrap_or(0);
            for i in 1..=count {
                if let Ok(sub) = folders.get_Item(&VARIANT::from(i)) {
                    walk(&sub, out);
                }
            }
        }
    }
}

unsafe fn read(task: &IRegisteredTask) -> Task {
    unsafe {
        let path = task.Path().map(|p| p.to_string()).unwrap_or_default();
        let enabled = task.Enabled().map(|b| b.as_bool()).unwrap_or(false);
        let mut author = BSTR::new();
        let mut actions = Vec::new();
        let definition = task.Definition();
        let unreadable = definition.is_err();
        if let Ok(def) = definition {
            if let Ok(info) = def.RegistrationInfo() {
                let _ = info.Author(&mut author);
            }
            if let Ok(collection) = def.Actions() {
                let mut count = 0;
                let _ = collection.Count(&mut count);
                for i in 1..=count {
                    let Ok(action) = collection.get_Item(i) else { continue };
                    let Ok(exec) = action.cast::<IExecAction>() else { continue };
                    let (mut exe, mut args) = (BSTR::new(), BSTR::new());
                    let _ = exec.Path(&mut exe);
                    let _ = exec.Arguments(&mut args);
                    actions.push((exe.to_string(), args.to_string()));
                }
            }
        }
        Task { path, enabled, author: author.to_string(), actions, unreadable }
    }
}
