import zipfile
import xml.etree.ElementTree as ET

def extract_text_from_docx(docx_path):
    with zipfile.ZipFile(docx_path) as docx:
        xml_content = docx.read('word/document.xml')
    tree = ET.XML(xml_content)
    namespace = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    texts = [node.text for node in tree.findall('.//w:t', namespace) if node.text]
    return ' '.join(texts)

print(extract_text_from_docx('BankSentinel_Hackathon_Plan_v2.docx'))
