import os
from time import sleep

from .reports import ScanReport

def run(before_path: str, after_path: str, xlsx_dir: str='reports', log_function=None):
    """Starts vulnerability parsing process."""
    if not log_function:
        log_function = lambda message: print(message)
        log_function('vulpa v0.99 - парсер отчётов об уязвимостях RedCheck\n')

    target_map = {}
    if os.path.exists('.tmap'):
        try:
            with open('.tmap', 'r') as tmap:
                lines = tmap.readlines()
                hosts = {}
                for line in lines:
                    host_addr, host_name = tuple(line.split('^'))
                    hosts[host_addr] = host_name.strip('\n')
                target_map = hosts
        except Exception:
            log_function('Обнаружен файл .tmap, но его формат неверный. Операция отменена\n')
            return 1
                
        log_function('Обнаружен файл .tmap - адреса указанных в нём хостов будут заменены на сопоставленные с ними имена\n')
        sleep(0.5)
    print(target_map)
    log_function('Запуск анализа дерева...')

    sr = ScanReport(before_path, xlsx_dir, target_map)
    log_function(f'Сканируется {sr.filename}')
    r = sr.parse_vulnerabilities()
    log_function(f'Завершено. Найдено {len(sr._definitions)} уязвимостей, проходов: {sum(map(lambda j: len(j), r.values()))}\n')
    log_function(f'Сохранение отчёта модернизации (путь: {xlsx_dir}/report_mod.xlsx)...\n')
    sr._export_mod_report()

    log_function('Запуск анализа дерева...')

    sr2 = ScanReport(after_path, xlsx_dir, target_map)
    log_function(f'Сканируется {sr2.filename}')
    r2 = sr2.parse_vulnerabilities()
    log_function(f'Завершено. Найдено {len(sr2._definitions)} уязвимостей, проходов: {sum(map(lambda j: len(j), r2.values()))}\n')
    log_function(f'Поиск исправленных уязвимостей...')
    sr.merge_fixes(sr2)
    log_function(f'Сохранение отчёта модернизации (путь: {xlsx_dir}/report_svc.xlsx)...\n')
    sr._export_svc_report()

    log_function('Готово')
    log_function(f'Хеш-сумма всех уязвимостей: {sr.check_definitions_hash()}\n')
    return 0