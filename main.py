"""
Точка входа в приложение analyzer.
"""
import logging
from src.logger import setup_logger
from src.analyzer import SecurityAnalyzer


def main():
    """
    Главная функция запуска приложения.
    """
    logger = setup_logger()
    logger.info(" Запуск приложения SIEM Analyzer ")

    analyzer = SecurityAnalyzer()
    logger.debug("Анализатор инициализирован. Порог критичности: %d", analyzer.severity_threshold)

    logger.info("Начало анализа событий...")
    stats = analyzer.get_statistics()
    logger.info("Анализ завершен. Всего событий: %d, Критических: %d",
                stats['total_events'], stats['critical_events'])

    logger.info("Генерация аналитического отчёта...")
    analyzer.generate_report()

    logger.info("Сохранение состояния анализатора...")
    analyzer.save_state()

    logger.info("Приложение успешно завершено")


if __name__ == "__main__":
    main()