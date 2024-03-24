
#[derive(Debug, Clone)]
pub struct VirtualRouterMachine {
    pub timer: Timer,
    pub state: States,
    pub event: Event
}

impl Default for VirtualRouterMachine {
    fn default() -> Self {
        VirtualRouterMachine {
            timer: Timer::default(),
            state: States::default(),
            event: Event::default()
        }
    }
}

impl VirtualRouterMachine {
    pub fn set_advert_timer(&mut self, duration: f32) {
        self.timer = Timer { t_type: TimerType::AdvertTimer, duration: duration };
    }

    pub fn set_master_down_time(&mut self, duration: f32) {
        self.timer = Timer { t_type: TimerType::MasterDownTimer, duration: duration };
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

#[derive(Debug, Clone)]
pub struct Timer {
    t_type: TimerType,
    duration: f32   
}

impl Default for Timer {
    fn default() -> Self {
        Timer {
            t_type: TimerType::default(),
            duration: f32::default()
        }
    }
}

#[derive(Debug, Clone)]
pub enum TimerType {
    MasterDownTimer, 
    AdvertTimer
}

impl Default for TimerType {
    fn default() -> Self {
        Self::MasterDownTimer
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Event {
    NoEvent,
    Startup, 
    Shutdown,
    MasterDown
}

impl Default for Event {
    fn default() -> Self {
        Event::NoEvent
    }
}
