from logging.config import dictConfig

# Set up default logging to stdout
dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s:%(name)s:%(module)s:%(funcName)s: %(message)s",
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
        "root": {"level": "DEBUG", "handlers": ["stdout.handler"]},
    }
)

from acme_project import cli

cli.main()
