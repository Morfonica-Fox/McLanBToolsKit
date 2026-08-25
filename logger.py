import logging

from _colorize import ANSIColors


LEVEL_SYMBOLS: dict[int, str] = {
    logging.CRITICAL: ANSIColors.RED + "[*]",
    logging.ERROR: ANSIColors.INTENSE_YELLOW + "[!]",
    logging.WARNING: ANSIColors.YELLOW + "[-]",
    logging.INFO: ANSIColors.WHITE + "[+]",
    logging.DEBUG: ANSIColors.GREY + "[$]",
}


class SymbolFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord):
        symbol = LEVEL_SYMBOLS.get(
            record.levelno,
            ANSIColors.MAGENTA + "[?]",
        )
        original_msg = record.getMessage()
        record.msg = f"{symbol}{ANSIColors.RESET} {original_msg}"
        return super().format(record)


handler = logging.StreamHandler()
handler.setFormatter(SymbolFormatter("%(message)s"))
logger = logging.getLogger(__name__)
logger.addHandler(handler)


if __name__ == "__main__":
    logger.setLevel(logging.DEBUG)

    logger.critical("critical")
    logger.error("error")
    logger.warning("warning")
    logger.info("info")
    logger.debug("debug")

    UNKNOWN = 100
    logger.log(UNKNOWN, "?")
