from flask_table import Table, Col
from flask_table.html import element


class URLCol(Col):
    def __init__(self, name, url_attr, id_attr, **kwargs):
        self.url_attr = url_attr
        self.id_attr = id_attr
        super(URLCol, self).__init__(name, **kwargs)

    def td_contents(self, item, attr_list):
        text = self.from_attr_list(item, attr_list)
        url = self.from_attr_list(item, [self.url_attr])
        id = self.from_attr_list(item, [self.id_attr])
        return element('a', {'href': url, 'id': id}, content=text)


class QueryTable(Table):
    classes = ['table', 'table-hover']
    thead_classes = ['thead-light']
    no_items = "No queries"
    query = URLCol('Query', url_attr='query_url', id_attr='id', attr='query_id')