import sys

from vulpa.parser import run

argv = sys.argv

if '--nogui' in argv or '--help' in argv:
    if '--help' in argv:
        print('python vulpa.py --nogui -b <before-path> -a <after-path> [-d <xlsx-directory="reports">]')
        print('    -b <path>:   путь к отчёту об уязвимостях "До"')
        print('    -a <path>:   путь к отчёту об уязвимостях "После"')
        print('    -d <path>:   (необязательно) путь к каталогу для сохранения выходных xlsx-файлов')
        print('    -n, --nogui: вход в консольный режим')
        print('    -h, --help:  эта справка\n')
        sys.exit(0)

    bf_path = None
    try:
        bf_index = argv.index('-b')
        bf_path = argv[bf_index + 1]
    except ValueError:
        print('Неверно указан путь к файлу "До"')
        print('Использование: python vulpa.py --nogui -b <before-path> -a <after-path> [-d <xlsx-directory="reports">]')
        sys.exit(1)

    af_path = None
    try:
        af_index = argv.index('-a')
        af_path = argv[af_index + 1]
    except ValueError:
        print('Неверно указан путь к файлу "После"')
        sys.exit(1)

    save_dir = 'reports'
    try:
        save_dir = argv.index('-d')
        save_dir = argv[save_dir + 1]
    except ValueError:
        print('Неверно указан путь к директории для сохранения xlsx-файлов')
        sys.exit(1)

    sys.exit(run(bf_path, af_path, save_dir))
else:
    import vulpa.gui