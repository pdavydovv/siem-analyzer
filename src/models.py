"""
Модели данных, содержащие именованный кортеж SecurityEvent для представления событий безопасности.
"""

from collections import namedtuple

SecurityEvent = namedtuple(
    "SecurityEvent",
    ["timestamp", "src_ip", "dst_ip", "protocol", "port", "event_type", "severity", "description"]
)

def demonstrate_immutability():
    """
    Демонстрация неизменяемости namedtuple. Попытка изменения поля с вызовом исключения.
    :return: True, если было перехвачено
    """
    event = SecurityEvent(
        timestamp="2026-06-13T10:00:00",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        protocol="tcp",
        port=443,
        event_type="connection",
        severity=5,
        description="Test event"
    )

    try:
        event.severity = 10
        return False
    except AttributeError as e:
        print(f"Именнованный кортеж неизменяем {e}")
        return True

if __name__ == "__main__":
    demonstrate_immutability()