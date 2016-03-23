from treelib import Tree, Node

class openstackData():
    def __init__(self):
        self.resources = Tree()
        self.resources.create_node('CMS','CMS')
        
    def insert_resource(self, data_dict, parent):
        tag = data_dict['name'] 
        self.resources.create_node(tag, tag, parent=parent, data=data_dict)
    
    def print_openstackData(self):
        self.resources.show(line_type="ascii-em")
    
    def delete_resource(self, tag):
        resp = self.resources.remove_node(tag)
        if resp < 1:
            raise Exception("Resource removal failed.")
    
    def get_resource(self, tag):
        resp = self.resources.get_node(tag)
        if not isinstance(resp, Node):
            raise Exception("Returned node is not of type Node")
        return resp
    
    def get_children_resources(self, tag):
        resp = self.resources.children(tag)
        if not isinstance(resp, list):
            raise Exception("Did not get a list")
        return resp

    def is_resource_present(self, tag):
        resp = self.resources.contains(tag)
        return resp
    
    def move_resource(self, tag, new_parent):
        self.resources.move_node(tag, new_parent)
