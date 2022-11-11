from logging.config import dictConfig

dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s:%(name)s:%(module)s:%(funcName)s: %(message)s",
            },
            "fullmodule": {
                "format": "[%(asctime)s] %(levelname)s:%(name)s:%(filename)s:%(funcName)s: %(message)s",
            },
        },
        "handlers": {
            "stdout.handler": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "level": "DEBUG",
                "formatter": "default",
            },
        },
        "loggers": {
            "werkzeug": {
                "level": "DEBUG",
                "handlers": ["stdout.handler"],
            },
        },
        "root": {"level": "DEBUG", "handlers": ["stdout.handler"]},
    }
)

from acme_project import cli

cli.main()
