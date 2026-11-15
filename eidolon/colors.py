import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

def rl_prompt_safe(s: str) -> str:
    return _ANSI_RE.sub(lambda m: f"\001{m.group(0)}\002", s)

class C:
    RESET    = "\033[0m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"

    RED      = "\033[38;2;255;60;100m"
    CRIMSON  = "\033[38;2;200;30;60m"
    GREEN    = "\033[38;2;0;255;140m"
    LIME     = "\033[38;2;140;255;80m"
    YELLOW   = "\033[38;2;255;210;60m"
    GOLD     = "\033[38;2;220;170;30m"
    CYAN     = "\033[38;2;0;240;255m"
    ELECTRIC = "\033[38;2;100;200;255m"
    BLUE     = "\033[38;2;80;130;255m"
    PURPLE   = "\033[38;2;170;90;255m"
    VIOLET   = "\033[38;2;130;60;220m"
    PINK     = "\033[38;2;255;90;200m"
    MAGENTA  = "\033[38;2;230;60;180m"
    GRAY     = "\033[38;2;120;130;150m"
    SILVER   = "\033[38;2;180;190;210m"
    WHITE    = "\033[38;2;240;245;250m"
    SPECTRAL = "\033[38;2;200;210;240m"
    SHADOW   = "\033[38;2;60;65;90m"

_COLOR_MAP = {
    "red": C.RED, "crimson": C.CRIMSON, "yellow": C.YELLOW, "lime": C.LIME,
    "gray": C.GRAY, "cyan": C.CYAN, "purple": C.PURPLE, "pink": C.PINK,
    "green": C.GREEN, "blue": C.BLUE,
}

def c(text, color_name):
    return f"{_COLOR_MAP.get(color_name, C.WHITE)}{text}{C.RESET}"