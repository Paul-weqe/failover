#[derive(Debug, Clone, Copy)]
pub struct VirtualRouterSystem {
    pub timers: Timers,
    pub state: States
}

impl Default for VirtualRouterSystem {
    fn default() -> Self {
        VirtualRouterSystem {
            timers: Timers::default(),
            state: States::default()
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum States {
    INIT, 
    BACKUP, 
    MASTER
}

impl Default for States {
    fn default() -> Self {
        States::INIT
    }
}


#[derive(Debug, Clone, Copy)]
pub enum Timers {
    MasterDownTimer(f32),
    AdverTimer(u8)
}


impl Default for Timers {
    fn default() -> Self {
        Timers::MasterDownTimer(f32::default())
    }
}

