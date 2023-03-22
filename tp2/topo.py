"""
sudo mn --custom ~/topo.py --topo 1-1 --controller=remote 
"""

from mininet.topo import Topo

class Topo_1_1( Topo ):
	"TP1, Exercicio 1"

	def build( self ):

		# Add hosts and switches
		host31 = self.addHost( 'h31', ip='10.0.10.31/24', mac='00:00:00:00:00:31' )
		host32 = self.addHost( 'h32' , ip='10.0.20.32/24', mac='00:00:00:00:00:32')
		host33 = self.addHost( 'h33' , ip='10.0.30.31/24', mac='00:00:00:00:00:33')

		switch3 = self.addSwitch( 's3' )

		host21 = self.addHost( 'h21' , ip='10.0.10.21/24', mac='00:00:00:00:00:21')
		host22 = self.addHost( 'h22' , ip='10.0.20.22/24', mac='00:00:00:00:00:22')
		host23 = self.addHost( 'h23' , ip='10.0.30.23/24', mac='00:00:00:00:00:23')

		switch2 = self.addSwitch( 's2' )

		host11 = self.addHost( 'h11' , ip='10.0.10.11/24', mac='00:00:00:00:00:11')
		host12 = self.addHost( 'h12' , ip='10.0.20.12/24', mac='00:00:00:00:00:12')
		host13 = self.addHost( 'h13' , ip='10.0.30.13/24', mac='00:00:00:00:00:13')

		switch1 = self.addSwitch( 's1' )

		switch0 = self.addSwitch( 's0' )

		# Add links
		self.addLink( switch3, host31 )
		self.addLink( switch3, host32 )
		self.addLink( switch3, host33 )
		
		self.addLink( switch2, host21 )
		self.addLink( switch2, host22 )
		self.addLink( switch2, host23 )

		self.addLink( switch1, host11 )
		self.addLink( switch1, host12 )
		self.addLink( switch1, host13 )
		
		self.addLink( switch0, switch1 )
		self.addLink( switch1, switch2 )
		self.addLink( switch2, switch3 )


topos = {
	'1-1': ( lambda: Topo_1_1() ),
	}
