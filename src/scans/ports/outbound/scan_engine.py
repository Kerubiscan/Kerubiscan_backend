from abc import ABC, abstractmethod
from typing import List

class ScanEnginePort(ABC):
    @abstractmethod
    def connect(self) -> bool:
        pass

    @abstractmethod
    def disconnect(self) -> None:
        pass
        
    @abstractmethod
    def create_target(self, name: str, hosts: List[str], port_list_id: str = "") -> str:
        """Create a target and return its ID"""
        pass
        
    @abstractmethod
    def create_task(self, name: str, target_id: str, scanner_id: str, config_id: str) -> str:
        """Create a scan task and return its ID"""
        pass
        
    @abstractmethod
    def start_task(self, task_id: str) -> str:
        """Start a task and return the report ID"""
        pass
        
    @abstractmethod
    def get_task_status(self, task_id: str) -> str:
        """Get the status of a task"""
        pass

    @abstractmethod
    def get_report(self, report_id: str) -> str:
        """Retrieve the raw XML report"""
        pass
