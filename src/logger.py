"""
Модуль настройки логирования для приложения.
"""
import logging


def setup_logger(log_file: str = "app.log") -> logging.Logger:
    """
    Настройка логирования в файл и консоль.

    :param log_file: Путь к файлу лога
    :return: Настроенный объект логгера
    """
    logger = logging.getLogger("Analyzer")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(logging.DEBUG)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        logger.addHandler(fh)
        logger.addHandler(ch)

    return logger