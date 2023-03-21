"""
sudo mn --custom ~/topo.py --topo 1-2 --controller=remote
--switch=ovsk --protocols=OpenFlow13 --mac
"""

from mininet.topo import Topo

class Topo_1_1( Topo ):
	"TP1, Exercicio 1"

	def build( self ):

		# Add hosts and switches
		host1 = self.addHost( 'h1' )
		host2 = self.addHost( 'h2' )
		host3 = self.addHost( 'h3' )
		host4 = self.addHost( 'h4' )

		switch1 = self.addSwitch( 's1' )

		# Add links
		self.addLink( switch1, host1 )
		self.addLink( switch1, host2 )
		self.addLink( switch1, host3 )
		self.addLink( switch1, host4 )


class Topo_1_2( Topo ):
	"TP1, Exercicio 2"

	def build( self ):

		# Add hosts and switches
		host1 = self.addHost( 'h1' )
		host2 = self.addHost( 'h2' )
		host3 = self.addHost( 'h3' )
		host4 = self.addHost( 'h4' )
		host5 = self.addHost( 'h5' )
		host6 = self.addHost( 'h6' )
		host7 = self.addHost( 'h7' )
		host8 = self.addHost( 'h8' )

		switch1 = self.addSwitch( 's1' )
		switch2 = self.addSwitch( 's2' )
		switch3 = self.addSwitch( 's3' )

		# Add links
		self.addLink( switch1, switch2 )
		self.addLink( switch1, switch3 )
		self.addLink( switch2, host1 )
		self.addLink( switch2, host2 )
		self.addLink( switch2, host3 )
		self.addLink( switch2, host4 )
		self.addLink( switch3, host5 )
		self.addLink( switch3, host6 )
		self.addLink( switch3, host7 )
		self.addLink( switch3, host8 )



topos = {
	'1-1': ( lambda: Topo_1_1() ),
	'1-2': ( lambda: Topo_1_2() )
	}
