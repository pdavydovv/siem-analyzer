"""
Модуль тестирования класса SecurityAnalyzer.
"""
import json
import pytest
from pathlib import Path
from src.analyzer import SecurityAnalyzer


@pytest.fixture
def mock_data_file(tmp_path):
    """
    Фикстура: создает временный файл с тестовыми данными.
    :param tmp_path: Временная директория pytest
    :return: Путь к временному файлу
    """
    data = [
        {"timestamp": "2023-01-01T10:00:00", "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "protocol": "tcp",
         "port": 80, "event_type": "connection", "severity": 3, "description": "test"},
        {"timestamp": "2023-01-01T11:00:00", "src_ip": "192.168.1.2", "dst_ip": "10.0.0.2", "protocol": "udp",
         "port": 53, "event_type": "network_scan", "severity": 7, "description": "test"},
        {"timestamp": "2023-01-01T12:00:00", "src_ip": "192.168.1.1", "dst_ip": "10.0.0.3", "protocol": "tcp",
         "port": 443, "event_type": "connection", "severity": 9, "description": "test"}
    ]
    file_path = tmp_path / "test_events.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return str(file_path)


class TestSecurityAnalyzer:
    """
    Тесты для класса SecurityAnalyzer.
    """

    def test_initialization(self, mock_data_file):
        """Тест инициализации анализатора (позитивный)."""
        analyzer = SecurityAnalyzer(data_file=mock_data_file)
        assert analyzer.severity_threshold == 5

    def test_get_events_by_severity(self, mock_data_file):
        """Тест фильтрации событий (позитивный)."""
        analyzer = SecurityAnalyzer(data_file=mock_data_file)
        events = analyzer.get_events_by_severity(threshold=5)
        assert len(events) == 2
        assert events[0].severity == 7
        assert events[1].severity == 9

    def test_count_by_event_type(self, mock_data_file):
        """Тест группировки событий по типу (позитивный)."""
        analyzer = SecurityAnalyzer(data_file=mock_data_file)
        counts = analyzer.count_by_event_type()
        assert counts["connection"] == 2
        assert counts["network_scan"] == 1

    def test_get_unique_ips(self, mock_data_file):
        """Тест извлечения уникальных IP-адресов (позитивный)."""
        analyzer = SecurityAnalyzer(data_file=mock_data_file)
        ips = analyzer.get_unique_ips()
        # 3 src + 3 dst, но 192.168.1.1 повторяется, итого 5 уникальных
        assert len(ips) == 5

    def test_get_statistics(self, mock_data_file):
        """Тест получения статистики (позитивный)."""
        analyzer = SecurityAnalyzer(data_file=mock_data_file)
        stats = analyzer.get_statistics()
        assert stats["total_events"] == 3
        assert stats["critical_events"] == 2

    def test_generate_report(self, mock_data_file, tmp_path):
        """Тест генерации отчета (позитивный)."""
        analyzer = SecurityAnalyzer(data_file=mock_data_file)
        report_path = str(tmp_path / "report.json")
        report = analyzer.generate_report(output_file=report_path)
        assert Path(report_path).exists()
        assert report["statistics"]["total_events"] == 3

    def test_to_dict_and_from_dict(self, mock_data_file):
        """Тест сериализации и десериализации состояния (позитивный)."""
        analyzer = SecurityAnalyzer(data_file=mock_data_file)
        analyzer.severity_threshold = 8
        state = analyzer.to_dict()

        new_analyzer = SecurityAnalyzer(data_file=mock_data_file)
        new_analyzer.from_dict(state)
        assert new_analyzer.severity_threshold == 8

    def test_save_and_load_state(self, mock_data_file, tmp_path):
        """Тест сохранения и загрузки состояния в файл (позитивный)."""
        analyzer = SecurityAnalyzer(data_file=mock_data_file)
        analyzer.severity_threshold = 9
        state_path = str(tmp_path / "state.json")
        analyzer.save_state(filepath=state_path)

        new_analyzer = SecurityAnalyzer(data_file=mock_data_file)
        new_analyzer.load_state(filepath=state_path)
        assert new_analyzer.severity_threshold == 9

    def test_boundary_values_setter(self, mock_data_file):
        """Тест граничных значений для сеттера порога (негативный)."""
        analyzer = SecurityAnalyzer(data_file=mock_data_file)
        with pytest.raises(ValueError):
            analyzer.severity_threshold = 0
        with pytest.raises(ValueError):
            analyzer.severity_threshold = 11

    def test_missing_file(self):
        """Тест отсутствия файла данных (негативный)."""
        analyzer = SecurityAnalyzer(data_file="non_existent_file.json")
        with pytest.raises(FileNotFoundError):
            list(analyzer._load_events())

    def test_corrupted_json(self, tmp_path):
        """Тест поврежденного JSON файла (негативный)."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{this is not json}")
        analyzer = SecurityAnalyzer(data_file=str(bad_file))
        with pytest.raises(json.JSONDecodeError):
            list(analyzer._load_events())

    def test_empty_data(self, tmp_path):
        """Тест пустых данных (граничный сценарий)."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("[]")
        analyzer = SecurityAnalyzer(data_file=str(empty_file))
        stats = analyzer.get_statistics()
        assert stats["total_events"] == 0
        assert stats["critical_events"] == 0