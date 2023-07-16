# GWs validator. We need it to have compatibility with puppet 3.x, 'cause it doesn't support each.
#
define network::mroute::validate_gw (
  Array[String] $routes,
) {
  $route = $routes[$name]
  if $route =~ Array {
    fail("Multiple gateways per route are not allowed on ${facts['os']['family']}")
  }
}
