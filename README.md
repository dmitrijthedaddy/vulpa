# vulpa
Парсер уязвимостей для RedCheck

В скрипт загружается два файла с отчётами о просканированных уязвимостях (до и после устранения). На выходе пользователь получает два xlsx-файла - форму для модернизации (report_mod.xlsx) и форму для сервисного обслуживания (report_svc.xlsx).

## Требования
* [Python 3.9](https://www.python.org/downloads/)
* [pandas](https://github.com/pandas-dev/pandas)
* Tcl/Tk для Python (для работы графического интерфейса)

## Графический режим
Для корректной работы GUI в системе необходимо наличие пакета `tkinter`. Под Windows его можно установить,
поставив чекбокс "Install Tcl/Tk" в инсталляторе Python, в Unix-подобных системах - установить из пакетного менеджера.
Без tkinter графический интерфейс не запустится.

Порядок работы:
1. В каталоге со скриптом выполнить команду `python vulpa.py`
2. Указать необходимые пути (относительные или абсолютные - неважно);
3. Нажать кнопку "Запустить";
4. xlsx-отчёты сохранятся в указанную папку.

## Консольный режим
У vulpa есть полноценный консольный режим, который может быть полезен для автоматизации создания отчётов
(например, в bash-скриптах). Для использования консольного режима необходимо указать ключ `-n` или `--nogui`.

Предположим, что xml-файлы первого сканирования "before.xml" и второго сканирования "after.xml" лежат в том же 
каталоге, что и скрипт. Результаты нужно сохранить в папку "reports" каталогом выше. Тогда синтаксис для запуска парсинга будет следующим:
```python vulpa.py --nogui -b before.xml -a after.xml -d ../reports```

## Файл соответствия хостов
В папку со скриптом (рядом с vulpa.py) при желании можно поместить файл .tmap, с помощью которого парсер в итоговых xlsx-файлах
заменит адреса указанных хостов на необходимые имена. При этом важно соблюдать синтаксис вида `IP_адрес^имя_хоста`. Например:
```
192.168.1.101^Компьютер 1
192.168.1.101^Компьютер 2
```

## Лицензия
MIT
