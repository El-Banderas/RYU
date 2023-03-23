
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def TP2():

	net = Mininet( controller=Controller, switch=OVSSwitch, waitConnected=True )

	info( "*** Creating controllers\n" )
	c1 = net.addController( 'switchVLAN', port=6633 )
	c2 = net.addController( 'LoadBalancer', port=6634 )


	info( "*** Floor 3\n" )
	host31 = net.addHost( 'h31', ip='10.0.10.31/24', mac='00:00:00:00:00:31' )
	host32 = net.addHost( 'h32' , ip='10.0.20.32/24', mac='00:00:00:00:00:32')
	host33 = net.addHost( 'h33' , ip='10.0.30.33/24', mac='00:00:00:00:00:33')

	switch3 = net.addSwitch( 's3' )

	info( "*** Floor 2\n" )
	host21 = net.addHost( 'h21' , ip='10.0.10.21/24', mac='00:00:00:00:00:21')
	host22 = net.addHost( 'h22' , ip='10.0.20.22/24', mac='00:00:00:00:00:22')
	host23 = net.addHost( 'h23' , ip='10.0.30.23/24', mac='00:00:00:00:00:23')

	switch2 = net.addSwitch( 's2' )

	info( "*** Floor 1\n" )
	host11 = net.addHost( 'h11' , ip='10.0.10.11/24', mac='00:00:00:00:00:11')
	host12 = net.addHost( 'h12' , ip='10.0.20.12/24', mac='00:00:00:00:00:12')
	host13 = net.addHost( 'h13' , ip='10.0.30.13/24', mac='00:00:00:00:00:13')

	switch1 = net.addSwitch( 's1' )

	info( "*** Servers\n" )
	server1 = net.addHost( 'h01' , ip='10.0.10.101/24', mac='00:00:00:00:01:01')
	server2 = net.addHost( 'h02' , ip='10.0.10.102/24', mac='00:00:00:00:01:02')
	server3 = net.addHost( 'h03' , ip='10.0.10.103/24', mac='00:00:00:00:01:03')

	switch0 = net.addSwitch( 's0' )


	info( "*** Creating links\n" )
	net.addLink( switch0, switch1 )
	net.addLink( switch1, switch2 )
	net.addLink( switch2, switch3 )

	net.addLink( switch3, host33 )
	net.addLink( switch3, host31 )
	net.addLink( switch3, host32 )
	
	net.addLink( switch2, host23 )
	net.addLink( switch2, host21 )
	net.addLink( switch2, host22 )

	net.addLink( switch1, host13 )
	net.addLink( switch1, host11 )
	net.addLink( switch1, host12 )

	net.addLink( switch0, server3 )
	net.addLink( switch0, server1 )
	net.addLink( switch0, server2 )


	info( "*** Starting network\n" )
	net.build()
	c1.start()
	c2.start()
	switch1.start([c1])
	switch2.start([c1])
	switch3.start([c1])
	switch0.start([c2])

	info( "*** Testing network\n" )
	net.pingAll()

	info( "*** Running CLI\n" )
	CLI(net)

	info( "*** Stopping network\n" )
	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )  # for CLI output
	TP2()