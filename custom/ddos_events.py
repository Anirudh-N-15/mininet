from ryu.controller.event import EventBase


class EventMitigationRequest(EventBase):
    def __init__(self, attacker_ip, victim_ip):
        super().__init__()
        self.attacker_ip = attacker_ip
        self.victim_ip = victim_ip