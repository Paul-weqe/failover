#[derive(Default, Debug, Clone)]
pub struct VirtualRouterMachine {
    pub timer: Timer,
    pub state: States,
    pub event: Event
}

impl VirtualRouterMachine {
    pub fn set_advert_timer(&mut self, duration: f32) {
        self.timer = Timer { t_type: TimerType::Adver, remaining_time: duration };
    }

    pub fn set_master_down_timer(&mut self, duration: f32) {
        self.timer =  Timer { t_type: TimerType::MasterDown, remaining_time: duration };
    }

    pub fn disable_timer(&mut self) {
        self.timer = Timer { t_type: TimerType::Null, remaining_time: f32::default() };
    }

    pub fn reduce_timer(&mut self) {
        self.timer.remaining_time = if self.timer.remaining_time == 0.0 { 0.0 } else { self.timer.remaining_time - 1.0 };
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
    pub remaining_time: f32   
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
