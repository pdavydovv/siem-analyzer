"""
Модуль для анализа событий безопасности
"""

import json
from collections import Counter
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Generator

from src.models import SecurityEvent
from src.data_generator import SecurityEventGenerator

class SecurityAnalyzer:
    """
    Анализатор, выполняющий фильтрацию, группировку и анализ
    """
    def __init__(self, data_file: str = "../data/events.json"):
        """
        Инициализация анализатора
        :param data_file: Путь к файлу с событиями
        """
        self._data_file = Path(data_file)
        self._severity_threshold = 5

    @property
    def severity_threshold(self) -> int:
        """
        Порог критичности для фильтрации
        :return: Текущий порог критичности
        """
        return self._severity_threshold

    @severity_threshold.setter
    def severity_threshold(self, value: int) -> None:
        """
        Установка порога критичности
        :param value: Новое значение порога
        :raises ValueError: Если значение вне диапазона 1-10
        """
        if not 1 <= value <= 10:
            raise ValueError("Оцена опасности может быть только от 1 до 10")
        self._severity_threshold = value

    def _load_events(self) -> Generator[SecurityEvent, None, None]:
        """
        Генератор для загрузки событий из файла. По очереди выдает объекты SecurityEvent.
        Ничего не принимает и не возвращает.
        :yield: Следующее событие из файла
        """
        generator = SecurityEventGenerator()
        yield from generator.load_from_json(str(self._data_file))

    def get_events_by_severity(self, threshold: int = None) -> List[SecurityEvent]:
        """
        Фильтрация событий с критичностью выше порога.
        :param threshold: Порог критичности
        :return: Отфильтрованный список событий, отсортированный по времени
        """
        if threshold is None:
            threshold = self._severity_threshold

        filtered = [
            event for event in self._load_events()
            if event.severity > threshold
        ]
        return sorted(filtered, key=lambda x: x.timestamp)

    def count_by_event_type(self) -> Counter:
        """
        Группировка событий по типу и подсчёт количества.
        :return:
        """
        event_types = [event.event_type for event in self._load_events()]
        return Counter(event_types)

    def get_unique_ips(self) -> set:
        """
        Извлечение всех уникальных IP-адресов
        :return: Множество уникальных IP-адресов
        """

        ips = set()
        for event in self._load_events():
            ips.add(event.src_ip)
            ips.add(event.dst_ip)
        return ips

    def get_statistics(self) -> Dict[str, Any]:
        """
        Получение полной статистики по событиям.
        :return: Словарь со статистикой
        """
        events_list = list(self._load_events())
        return {
            "total_events": len(events_list),
            "critical_events": len([e for e in events_list if e.severity > self._severity_threshold]),
            "unique_ips_count": len(self.get_unique_ips()),
            "event_types": dict(self.count_by_event_type()),
            "severity_threshold": self._severity_threshold,
            "date_range": {
                "start": min(e.timestamp for e in events_list) if events_list else None,
                "end": max(e.timestamp for e in events_list) if events_list else None
            }
        }

    def generate_report(self, output_file: str = "../data/report.json") -> Dict[str, Any]:
        """
        Генерация аналитического отчёта в json
        :param output_file: Путь к файлу для сохранения отчёта
        :return: Словарь с данными отчёта
        """
        report = {
            "generated_at": datetime.now().isoformat(),
            "configuration": {
                "data_file": str(self._data_file),
                "severity_threshold": self._severity_threshold
            },
            "statistics": self.get_statistics(),
            "critical_events": [
                event._asdict() for event in self.get_events_by_severity()
            ],
            "unique_ips": sorted(list(self.get_unique_ips())),
            "event_type_distribution": dict(self.count_by_event_type())
        }
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"Отчёт сохранён в {output_file}")
        return report

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация состояния анализатора в словарь.
        :return: Словарь с состоянием объекта
        """
        return {
            "data_file": str(self._data_file),
            "severity_threshold": self._severity_threshold
        }

    def from_dict(self, data: Dict[str, Any]) -> None:
        """
        Загрузка состояния анализатора из словаря.
        :param data: Словарь с данными для загрузки
        :return:
        """
        if "data_file" in data:
            self._data_file = Path(data["data_file"])
        if "severity_threshold" in data:
            self._severity_threshold = data["severity_threshold"]

    def save_state(self, filepath: str = "../data/analyzer_state.json") -> None:
        """
        Сохранение состояния объекта в JSON файл
        :param filepath: Путь к файлу для сохранения
        :return: Сохраненный файл
        """
        state = self.to_dict()
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

        print(f"Состояние сохранено в {filepath}")

    def load_state(self, filepath: str = "../data/analyzer_state.json") -> None:
        """
        Загрузка состояния объекта из JSON файла
        :param filepath: Путь к файлу с состоянием
        :return: Загрузка состояния из объекта
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            state = json.load(f)
        self.from_dict(state)
        print(f"Состояние загружено из {filepath}")


if __name__ == "__main__":
    analyzer = SecurityAnalyzer()

    stats = analyzer.get_statistics()
    print(f"Всего событий: {stats['total_events']}")
    print(f"Критических событий (severity > {stats['severity_threshold']}): {stats['critical_events']}")
    print(f"Уникальных IP: {stats['unique_ips_count']}")

    for event_type, count in analyzer.count_by_event_type().most_common():
        print(f"{event_type}: {count}")

    analyzer.generate_report()
    analyzer.save_state()