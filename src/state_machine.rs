
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
        self.timer = Timer { t_type: TimerType::AdvertTimer, remaining_time: duration };
    }

    pub fn set_master_down_timer(&mut self, duration: f32) {
        self.timer =  Timer { t_type: TimerType::MasterDownTimer, remaining_time: duration };
    }

    pub fn disable_timer(&mut self) {
        self.timer = Timer { t_type: TimerType::NoTimer, remaining_time: f32::default() };
    }

    pub fn reduce_timer(&mut self) {
        self.timer.remaining_time = if self.timer.remaining_time == 0.0 { 0.0 } else { self.timer.remaining_time - 1.0 };
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Timer {
    pub t_type: TimerType,
    pub remaining_time: f32   
}

impl Default for Timer {
    fn default() -> Self {
        Timer {
            t_type: TimerType::default(),
            remaining_time: f32::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimerType {
    MasterDownTimer, 
    AdvertTimer,
    NoTimer
}

impl Default for TimerType {
    fn default() -> Self {
        Self::NoTimer
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Event {
    NoEvent,
    Startup, 
    Shutdown,
    MasterDown
}

impl Default for Event {
    fn default() -> Self {
        Event::Startup
    }
}