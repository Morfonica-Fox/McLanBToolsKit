import logging

from _colorize import ANSIColors

LEVEL_SYMBOLS: dict[int, str] = {
    logging.CRITICAL: ANSIColors.RED + "[*]" + ANSIColors.RESET,
    logging.ERROR: ANSIColors.INTENSE_YELLOW + "[!]" + ANSIColors.RESET,
    logging.WARNING: ANSIColors.YELLOW + "[-]" + ANSIColors.RESET,
    logging.INFO: ANSIColors.WHITE + "[+]" + ANSIColors.RESET,
    logging.DEBUG: ANSIColors.GREY + "[$]" + ANSIColors.RESET,
}


class SymbolFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord):
        symbol = LEVEL_SYMBOLS.get(
            record.levelno,
            ANSIColors.MAGENTA + "[?]" + ANSIColors.RESET,
        )
        original_msg = record.getMessage()
        record.msg = f"{symbol} {original_msg}"
        return super().format(record)


handler = logging.StreamHandler()
handler.setFormatter(SymbolFormatter("%(message)s"))
logger = logging.getLogger(__name__)
logger.addHandler(handler)

# logger.setLevel(logging.DEBUG)


if __name__ == "__main__":
    logger.critical("critical")
    logger.error("error")
    logger.warning("warning")
    logger.info("info")
    logger.debug("debug")

    UNKNOWN = 100
    logger.log(UNKNOWN, "?")
