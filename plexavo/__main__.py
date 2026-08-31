"""Allow `python -m plexavo` (and `py -m plexavo` on Windows) to launch the CLI.

This is the exact same entry point as the installed `plexavo` command, so
running it with no arguments still opens the interactive menu. It exists so
Windows users can install with plain `pip` and run the tool without going
through the generated `plexavo.exe` launcher, which Windows Smart App Control
blocks on some machines (it's unsigned). See the README's Install section.
"""

from plexavo.cli import main

if __name__ == "__main__":
    main()
