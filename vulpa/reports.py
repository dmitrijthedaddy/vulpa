"""
report.py

Provides a bunch of classes to parse, merge & analyze RedCheck reports of different types
"""

import os
import xml.etree.ElementTree as et

import pandas as pd

from .entities import ScanTarget, VulnerabilityDefinition
from .tools import _flush_refs_for_remediation, _check_reports_dir

class BaseReport:
    """
    A base structure for RedCheck report.
    Analyzes entire XML tree, gets scan targets, finds definitions of report results
    and stores them in private fields for future use.
    """
    def __init__(self, filename: str, save_dir: str, tmap: dict):
        self.filename = filename
        self.save_dir = save_dir
        self.tmap = tmap
        _check_reports_dir(self.save_dir)
        self._prepare_root()
        self._scan_targets()
        self._scan_definitions()

    def _prepare_root(self):
        self._root = et.parse(self.filename)

    def _scan_targets(self):
        self._targets = []
        targets_node = self._root.find('catalogs/targets')
        for target in targets_node:
            t = ScanTarget(
                target.attrib['inner_id'],
                target.find('address').text,
                self.tmap.get(target.find('address').text, ''),
                target.find('description').text,
                target.find('cpe').text)
            self._targets.append(t)

    def _scan_definitions(self):
        self._definitions = []
        definitions_node = self._root.find('catalogs/definitions')
        for definition in definitions_node:
            d = VulnerabilityDefinition(
                definition.attrib['inner_id'],
                definition.find('title').text,
                '',
                definition.find('description').text,
                definition.attrib['severity'],
                definition.attrib['remediation'],
                {source: url for source, url in zip(
                    map(lambda ref: ref.attrib['source'], definition.findall('reference')), 
                    map(lambda ref: { 'ref_id': ref.attrib.get('ref_id', ''), 'ref_url': ref.attrib.get('ref_url', '') }, definition.findall('reference'))
                )},
                [],
                False
            )
            self._definitions.append(d)

    def check_definitions_hash(self):
        return hash(';'.join(sorted(list(map(lambda d: d.cpe, self._definitions)))))


class ScanReport(BaseReport):
    """
    Representation of RedCheck vulnerability scan report.
    """
    def __init__(self, filename: str, save_dir: str, tmap: dict):
        super().__init__(filename, save_dir, tmap)
        self.merged = False

    def parse_vulnerabilities(self):
        vuls = {}
        total = 0
        job_nodes = self._root.findall('body/job_report')
        for job_node in job_nodes:
            job_title = job_node.find('job').text
            vuls[job_title] = []
            target_reports = job_node.findall('target_report')
            for target_report in target_reports:
                current_target = next(filter(lambda t: t.inner_id == target_report.find('target').text, self._targets), None)
                vulnerabilities = target_report.findall('result/vulnerability')
                for vulnerability in vulnerabilities:
                    current_vul = next(filter(lambda v: v.inner_id == vulnerability.attrib['inner_id'], self._definitions), None)
                    current_vul.cpe = vulnerability.find('products/product').text
                    current_vul.targets.append(current_target)
                    vuls[job_node.find('job').text].append(current_vul)
        self._vuls = vuls
        return vuls

    def merge_fixes(self, merging_report):
        vuls = self._vuls
        m_vuls = merging_report._vuls
        for job_t, job_m in zip(vuls.values(), m_vuls.values()):
            for vul in job_t:
                if not next(filter(lambda v: v.inner_id == vul.inner_id, job_m), None):
                    vul.fixed = True
        self.merged = True

    def _export_mod_report(self):
        writer = pd.ExcelWriter(self.save_dir + '/report_mod.xlsx', engine='xlsxwriter')

        df = pd.DataFrame({
            'Место установки (ИМЯ)': list(
                map(lambda d: ', '.join(sorted(list(
                    map(lambda t: t.name if t.name else t.address, d.targets)))
                ), self._definitions)),
            'Группа программного обеспечения (Тип ПО)': list(
                map(lambda d: d.cpe, self._definitions)),
            'Тип уязвимости (описание)': list(
                map(lambda d: d.title, self._definitions)),
            '№ в БДУ ФСТЭК': list(
                map(lambda d: d.references.get('FSTEC', {}).get('ref_url', ''), self._definitions)),
            'Уровень риска': list(
                map(lambda d: d.severity, self._definitions)),
            'Возможные меры по устранению уязвимости': list(
                map(lambda d: f'{d.remediation}\n' + next(map(lambda r: r.get('ref_url', ''),
                    _flush_refs_for_remediation(d.references).values())
                ),
                self._definitions)),
            'Реализованные меры по устранению уязвимости': ['' for _ in range(len(self._definitions))]})

        df.to_excel(writer, sheet_name='Модернизация', startrow=1, header=False)
        workbook = writer.book
        worksheet = writer.sheets['Модернизация']

        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'align': 'center',
            'valign': 'vcenter',
            'bg_color': '#FFC000',
            'border': 1})
        cell_format = workbook.add_format({
            'text_wrap': True,
            'align': 'center',
            'valign': 'vcenter',
            'border': 1})

        for c_num, v in enumerate(df.columns.values):
            worksheet.write(0, c_num + 1, v, header_format)

        worksheet.set_column(1, 7, 40)
        for _ in range(len(self._definitions)):
            worksheet.set_row(_, 60, cell_format)

        writer.save()

    def _export_svc_report(self):
        if not self.merged:
            raise Exception('Report isn`t completed with fixes yet. Use ScanReport.merge_fixes()')

        writer = pd.ExcelWriter(self.save_dir + '/report_svc.xlsx', engine='xlsxwriter')

        df = pd.DataFrame({
            'Место установки (IP)': list(
                map(lambda d: ', '.join(sorted(list(
                    map(lambda t: t.name if t.name else t.address, d.targets)))
                ), self._definitions)),
            'Группа программного обеспечения (Тип ПО)': list(
                map(lambda d: d.cpe, self._definitions)),
            'Тип уязвимости (описание)': list(
                map(lambda d: d.title, self._definitions)),
            '№ в БД общеизвестных уязвимостей': list(
                map(lambda d: d.references.get('FSTEC', {}).get('ref_url', ''), self._definitions)),
            'Уровень риска': list(
                map(lambda d: d.severity, self._definitions)),
            'БДУ ФСТЭК (+/-)': list(
                map(lambda d: '+' if d.references.get('FSTEC', None) else '-', self._definitions)),
            'Возможные меры по устранению уязвимости': list(
                map(lambda d: f'{d.remediation}\n' + next(map(lambda r: r.get('ref_url', ''),
                    _flush_refs_for_remediation(d.references).values())
                ),
                self._definitions)),
            'Реализованная мера защиты': ['' for _ in range(len(self._definitions))],
            'Устранена? (Да/Нет)': list(
                map(lambda d: 'Да' if d.fixed else 'Нет', self._definitions)),
            'Рекомендации по устранению': ['' for _ in range(len(self._definitions))]})
        
        df.to_excel(writer, sheet_name='Сервисное обслуживание', startrow=1, header=False)
        workbook = writer.book
        worksheet = writer.sheets['Сервисное обслуживание']

        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'align': 'center',
            'valign': 'vcenter',
            'bg_color': '#FFC000',
            'border': 1})
        cell_format = workbook.add_format({
            'text_wrap': True,
            'align': 'center',
            'valign': 'vcenter',
            'border': 1})

        for c_num, v in enumerate(df.columns.values):
            worksheet.write(0, c_num + 1, v, header_format)
        worksheet.set_column(1, 7, 25)
        for _ in range(len(self._definitions)):
            worksheet.set_row(_, 60, cell_format)

        writer.save()

    def export_to_xlsx(self, variation: str='svc'):
        pass


class PatchReport(BaseReport):
    """Unfinished realisation of RedCheck patch report. Feel free to develop it (;"""
    def __init__(self, filename: str):
        super().__init__(filename)