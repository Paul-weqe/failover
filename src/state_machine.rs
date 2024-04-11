use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct VirtualRouterMachine {
    pub timer: Timer,
    pub state: States,
    pub event: Event
}


impl VirtualRouterMachine {

    pub fn set_advert_timer(&mut self, duration: f32) {
        self.timer = Timer { 
            t_type: TimerType::Adver, 
            remaining_time: duration,
            waiting_for: Some(Instant::now() + Duration::from_secs_f32(duration))
        };
    }

    pub fn set_master_down_timer(&mut self, duration: f32) {
        self.timer =  Timer { 
            t_type: TimerType::MasterDown, 
            remaining_time: duration, 
            waiting_for: Some(Instant::now() + Duration::from_secs_f32(duration)) 
        };
    }

    pub fn disable_timer(&mut self) {
        self.timer = Timer { 
            t_type: TimerType::Null, 
            remaining_time: f32::default(),
            waiting_for: None 
        };
    }

}


#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub enum States {
    #[default]
    Init, 
    Backup, 
    Master
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct Timer {
    pub t_type: TimerType,
    pub remaining_time: f32,
    pub waiting_for: Option<Instant>
}


#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub enum TimerType {
    #[default]
    Null,

    MasterDown, 
    Adver
}


#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Event {
    #[default]
    Startup,

    Null, 
    Shutdown,
    MasterDown
}
