"""Custom topology example

create a triangle topology with 3 switches s1, s2 and s3
"""

from mininet.topo import * 

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )
	
	# Adding Switches, Hosts, Edges
	self.add_node(1, Node())
	self.add_node(2, Node())
	self.add_node(3, Node())
	self.add_edge(1, 2, Edge())
	self.add_edge(1, 3, Edge())
	self.add_edge(2, 3, Edge())
	self.add_node(4, Node(is_switch = False))
	self.add_node(5, Node(is_switch = False))
	self.add_edge(4, 1, Edge())
	self.add_edge(5, 1, Edge())
	self.add_node(6, Node(is_switch = False))
	self.add_node(7, Node(is_switch = False))
	self.add_edge(6, 2, Edge())
	self.add_edge(7, 2, Edge())
	self.add_node(8, Node(is_switch = False))
	self.add_edge(8, 3, Edge())
	
	self.enable_all()
		
topos = { 'mytopo': ( lambda: MyTopo() ) }
