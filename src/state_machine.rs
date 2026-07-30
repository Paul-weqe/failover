use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct VirtualRouterMachine {
    pub(crate) timer: Timer,
    pub(crate) state: State,
    pub(crate) event: Event,
}

impl VirtualRouterMachine {
    pub fn set_advert_timer(&mut self, duration: f32) {
        self.timer = Timer {
            t_type: TimerType::Adver,
            remaining_time: duration,
            waiting_for: Some(
                Instant::now() + Duration::from_secs_f32(duration),
            ),
        };
    }

    pub fn set_master_down_timer(&mut self, duration: f32) {
        self.timer = Timer {
            t_type: TimerType::MasterDown,
            remaining_time: duration,
            waiting_for: Some(
                Instant::now() + Duration::from_secs_f32(duration),
            ),
        };
    }

    pub fn disable_timer(&mut self) {
        self.timer = Timer {
            t_type: TimerType::Null,
            remaining_time: f32::default(),
            waiting_for: None,
        };
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub(crate) enum State {
    #[default]
    Init,
    Backup,
    Master,
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub(crate) struct Timer {
    pub t_type: TimerType,
    pub remaining_time: f32,
    pub waiting_for: Option<Instant>,
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub(crate) enum TimerType {
    #[default]
    Null,

    MasterDown,
    Adver,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[allow(dead_code)]
pub(crate) enum Event {
    #[default]
    Startup,
    Null,
    Shutdown,
    MasterDown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_advert_timer_sets_type_and_duration() {
        let mut fsm = VirtualRouterMachine::default();
        fsm.set_advert_timer(1.5);

        assert_eq!(fsm.timer.t_type, TimerType::Adver);
        assert_eq!(fsm.timer.remaining_time, 1.5);
        assert!(fsm.timer.waiting_for.is_some());
        assert!(fsm.timer.waiting_for.unwrap() > Instant::now());
    }

    #[test]
    fn set_master_down_timer_sets_type_and_duration() {
        let mut fsm = VirtualRouterMachine::default();
        fsm.set_master_down_timer(3.5);

        assert_eq!(fsm.timer.t_type, TimerType::MasterDown);
        assert_eq!(fsm.timer.remaining_time, 3.5);
        assert!(fsm.timer.waiting_for.is_some());
        assert!(fsm.timer.waiting_for.unwrap() > Instant::now());
    }

    #[test]
    fn disable_timer_clears_type_duration_and_deadline() {
        let mut fsm = VirtualRouterMachine::default();
        fsm.set_advert_timer(1.0);

        fsm.disable_timer();

        assert_eq!(fsm.timer.t_type, TimerType::Null);
        assert_eq!(fsm.timer.remaining_time, 0.0);
        assert!(fsm.timer.waiting_for.is_none());
    }

    #[test]
    fn setting_a_new_timer_overwrites_the_previous_one() {
        let mut fsm = VirtualRouterMachine::default();
        fsm.set_master_down_timer(3.0);
        fsm.set_advert_timer(1.0);

        assert_eq!(fsm.timer.t_type, TimerType::Adver);
        assert_eq!(fsm.timer.remaining_time, 1.0);
    }
}
