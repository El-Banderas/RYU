"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        host1 = self.addHost( 'h1' )
        host2 = self.addHost( 'h2' )
        host3 = self.addHost( 'h3' )
        host4 = self.addHost( 'h4' )
        switch1 = self.addSwitch( 's1' )
        # Add links
        self.addLink( host1, switch1 )
        self.addLink( host2, switch1 )
        self.addLink( host3, switch1 )
        self.addLink( host4, switch1 )

		
        host5 = self.addHost( 'h5' )
        host6 = self.addHost( 'h6' )
        host7 = self.addHost( 'h7' )
        host8 = self.addHost( 'h8' )
        switch2 = self.addSwitch( 's2' )
        # Add links
        self.addLink( host5, switch2 )
        self.addLink( host6, switch2 )
        self.addLink( host7, switch2 )
        self.addLink( host8, switch2 )

	
        switch3 = self.addSwitch( 's3' )
        # Add links
        self.addLink( switch1, switch3 )
        self.addLink( switch2, switch3 )



topos = { 'mytopo': ( lambda: MyTopo() ) }
