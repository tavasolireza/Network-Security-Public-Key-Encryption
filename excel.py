from openpyxl.workbook import Workbook

headers = ['client username', 'client public key', 'server private key']
workbook_name = 'secret_table.xlsx'
wb = Workbook()
page = wb.active
page.title = 'Public Key Table'
page.append(headers)
wb.save(filename=workbook_name)
