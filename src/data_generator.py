"""
Модуль генерации данных через Faker.
"""
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from faker import Faker

from src.models import SecurityEvent


class SecurityEventGenerator:
    """
    Генератор событий с различными атрибутами
    """
    PROTOCOLS = ['tcp', 'udp', 'icmp', 'http', 'https', 'ssh', 'ftp', 'dns']
    EVENT_TYPES = [
        'connection', 'authentication', 'file_access', 'network_scan',
        'malware_detected', 'intrusion_attempt', 'data_exfiltration',
        'privilege_escalation', 'config_change', 'system_error'
    ]
    SEVERITY_LEVELS = list(range(1, 11))

    def __init__(self, locale='ru_RU'):
        """
        Инициализация генератора.
        :param locale: Локаль для Faker
        """
        self.fake = Faker(locale)
        self.fake.add_provider('internet')

    def generate_event(self, timestamp: datetime) -> SecurityEvent:
        """
        Генерация одного события безопасности
        :param timestamp: Временная метка события
        :return: Сгенерированное событие
        """
        return SecurityEvent(
            timestamp=timestamp.isoformat(),
            src_ip=self.fake.ipv4(),
            dst_ip=self.fake.ipv4(),
            protocol=random.choice(self.PROTOCOLS),
            port=random.randint(1, 65535),
            event_type=random.choice(self.EVENT_TYPES),
            severity=random.choice(self.SEVERITY_LEVELS),
            description=self._generate_description()
        )

    def _generate_description(self) -> str:
        """
        Генерация текстового описания события.
        :return: Текстовое описание события
        """
        actions = [
            "Попытка подключения", "Обнаружена аномалия", "Заблокирован доступ",
            "Зафиксирована активность", "Обнаружена уязвимость", "Выполнена команда",
            "Изменены настройки", "Создана учетная запись"
        ]
        targets = [
            "к серверу базы данных", "к файловому хранилищу", "к веб-приложению",
            "к контроллеру домена", "к почтовому серверу", "к сетевому оборудованию"
        ]
        return f"{random.choice(actions)} {random.choice(targets)}"

    def generate_events(self, count: int = 1000, start_date: datetime = None) -> list[SecurityEvent]:
        """
        Генерация списка событий.
        :param count: Количество событий для генерации
        :param start_date: Начальная дата для генерации
        :return: Список сгенерированных событий, отсортированный по времени
        """
        if start_date is None:
            start_date = datetime.now() - timedelta(days=30)

        events = []
        for i in range(count):
            timestamp = start_date + timedelta(seconds=random.randint(0, 30 * 24 * 60 * 60))
            events.append(self.generate_event(timestamp))

        events.sort(key=lambda x: x.timestamp)
        return events

    def save_to_json(self, events: list[SecurityEvent], filepath: str = "../data/events.json") -> None:
        """
        Сохранение событий в JSON.
        :param events: Список событий для сохранения
        :param filepath: Путь к файлу для сохранения
        """
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        events_dict = [event._asdict() for event in events]

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(events_dict, f, ensure_ascii=False, indent=2)

        print(f"Сгенерировано и сохранено {len(events)} событий в {filepath}")

    def load_from_json(self, filepath: str = "../data/events.json"):
        """
        Генератор для загрузки событий из JSON
        :param filepath: Путь к файлу с данными
        :yield: Следующее событие из файла
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            events = json.load(f)
            for event_dict in events:
                yield SecurityEvent(**event_dict)


def generate_sample_data(count: int = 1000):
    """
    Вспомогательная функция для генерации и сохранения тестовых данных
    :param count: Количество событий для генерации
    """
    generator = SecurityEventGenerator()
    events = generator.generate_events(count=count)
    generator.save_to_json(events)

    print("\nПроверка неизменяемости namedtuple:")
    from src.models import demonstrate_immutability
    demonstrate_immutability()


if __name__ == "__main__":
    generate_sample_data(1000)