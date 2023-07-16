#
# = Class: network
#
# This class installs and manages network
#
#
# == Parameters
#
# [*gateway*]
#   String. Optional. Default: undef
#   The default gateway of your system
#
# [*hostname*]
#   String. Optional. Default: undef
#   The hostname of your system
#
# [*config_file_notify*]
#   String or Boolean. Optional. Default: 'class_default'
#   Defines the content of the notify parameter on the resources which
#   change network settings.
#   The default string 'class_default' triggers network restart as defined
#   by command service_restart_exec
#   Set to undef or Boolean false to remove any notify, leave default value or
#   set Boolean true to use class defaults, or define, as a string,
#   the name(s) of the resources to notify. Ie: 'Service[network]',
#
# [*config_file_require*]
#   String or Boolean. Optional. Default: undef,
#   Defines the require argument of resources which handle network settings.
#   The default is to leave this undefined and don't force any dependency.
#   Set the name of a resource to require (must be in the catalog) for custom
#   need Ie: 'Package[network-tools]'
#
# [*interfaces_hash*]
#   Hash. Default undef.
#   The complete interfaces configuration (nested) hash
#   Needs this structure:
#   - First level: Interface name
#   - Second level: Interface options (check network::interface for the
#     available options)
#   If an hash is provided here, network::interface defines are declared with:
#   create_resources("network::interface", $interfaces_hash)
#
# [*routes_hash*]
#   Hash. Default undef.
#   The complete routes configuration (nested) hash
#   If an hash is provided here, network::route defines are declared with:
#   create_resources("network::route", $routes_hash)
#
# [*mroutes_hash*]
#   Hash. Default undef.
#   An hash of multiple route to be applied
#   If an hash is provided here, network::mroute defines are declared with:
#   create_resources("network::mroute", $mroutes_hash)
#
# [*rules_hash*]
#   Hash. Default undef.
#   An hash of ip rules to be applied
#   If an hash is provided here, network::rules defines are declared with:
#   create_resources("network::rules", $rules_hash)
#
# [*tables_hash*]
#   Hash. Default undef.
#   An hash of routing tables to be applied
#   If an hash is provided here, network::routing_table defines are declared with:
#   create_resources("network::routing_table", $tables_hash)
#
# [*confs_hash*]
#   Hash. Default undef.
#   An hash of network:::conf defines to apply.
#   If an hash is provided here, network::conf defines are declared with:
#   create_resources("network::conf", $conf_hash)
#
class network (

  Optional[String] $hostname                  = undef,

  Optional[Hash] $interfaces_hash           = undef,
  Optional[Hash] $routes_hash               = undef,
  Optional[Hash] $mroutes_hash              = undef,
  Optional[Hash] $rules_hash                = undef,
  Optional[Hash] $tables_hash               = undef,
  Optional[Hash] $confs_hash                = undef,

  String $hostname_file_template   = "network/hostname-${facts['os']['family']}.erb",

  # Parameter used only on RedHat family
  Optional[Stdlib::IP::Address] $gateway                   = undef,
  Optional[Enum['yes','no']] $nozeroconf                = undef,
  Optional[Enum['yes','no']] $ipv6enable                = undef,

  # Stdmod commons
  String $package_name,
  Enum['absent','present'] $package_ensure            = 'present',

  String $service_restart_exec,

  String $config_file_path,
  Optional[String] $config_file_require       = undef,
  String $config_file_notify        = 'class_default',
  Optional[String] $config_file_source        = undef,
  Optional[String] $config_file_template      = undef,
  Optional[String] $config_file_content       = undef,
  Optional[Hash] $config_file_options_hash  = undef,

  Boolean $config_file_per_interface = false,

  String $config_dir_path,
  Optional[String] $config_dir_source         = undef,
  Boolean $config_dir_purge          = false,
  Boolean $config_dir_recurse        = true,

  Optional[String] $dependency_class          = undef,
  Optional[String] $my_class                  = undef,

  Optional[String] $monitor_class             = undef,
  Optional[Hash] $monitor_options_hash      = undef,

  Optional[String] $firewall_class            = undef,
  Optional[Hash] $firewall_options_hash     = undef,

  String $scope_hash_filter         = '(uptime.*|timestamp)',

  Optional[Integer] $tcp_port                  = undef,
  Optional[Integer] $udp_port                  = undef,

  Boolean $hiera_merge               = false,

) {
  case $facts['os']['family'] {
    'Debian','RedHat','Amazon','Suse', 'Solaris': {}
    default: {
      fail("${facts['os']['name']} not supported.")
    }
  }
  # Hiera import

  if( $hiera_merge == true ) {
    $hiera_interfaces_hash = hiera_hash("${module_name}::interfaces_hash",undef)
    $real_interfaces_hash = $hiera_interfaces_hash ? {
      undef   => $interfaces_hash,
      default => $hiera_interfaces_hash,
    }

    $hiera_routes_hash = hiera_hash('network::routes_hash',undef)
    $real_routes_hash = $hiera_routes_hash ? {
      undef   => $routes_hash,
      default => $hiera_routes_hash,
    }

    $hiera_mroutes_hash = hiera_hash('network::mroutes_hash',undef)
    $real_mroutes_hash = $hiera_mroutes_hash ? {
      undef   => $mroutes_hash,
      default => $hiera_mroutes_hash,
    }
    $hiera_rules_hash = hiera_hash('network::rules_hash',undef)
    $real_rules_hash = $hiera_rules_hash ? {
      undef   => $rules_hash,
      default => $hiera_rules_hash,
    }
    $hiera_tables_hash = hiera_hash('network::tables_hash',undef)
    $real_tables_hash = $hiera_tables_hash ? {
      undef   => $tables_hash,
      default => $hiera_tables_hash,
    }
    $hiera_confs_hash = hiera_hash('network::confs_hash',undef)
    $real_confs_hash = $hiera_confs_hash ? {
      undef   => $confs_hash,
      default => $hiera_confs_hash,
    }
  }
  else {
    $real_interfaces_hash = $interfaces_hash
    $real_routes_hash     = $routes_hash
    $real_mroutes_hash    = $mroutes_hash
    $real_rules_hash      = $rules_hash
    $real_tables_hash     = $tables_hash
    $real_confs_hash      = $confs_hash
  }

  # Class variables validation and management

  $manage_config_file_content = $config_file_content ? {
    undef => $config_file_template ? {
      undef   => undef,
      default => template($config_file_template),
    },
    default => $config_file_content,
  }

  $manage_config_file_notify  = $config_file_notify ? {
    'class_default' => "Exec[${service_restart_exec}]",
    'undef'         => undef,
    ''              => undef,
    undef           => undef,
    true            => "Exec[${service_restart_exec}]",
    false           => undef,
    default         => $config_file_notify,
  }

  $manage_config_file_require  = $config_file_require ? {
    'class_default' => undef,
    'undef'         => undef,
    ''              => undef,
    undef           => undef,
    true            => undef,
    false           => undef,
    default         => $config_file_require,
  }

  $manage_hostname = pick($hostname, $facts['networking']['fqdn'])

  if $package_ensure == 'absent' {
    $config_dir_ensure = absent
    $config_file_ensure = absent
  } else {
    $config_dir_ensure = directory
    $config_file_ensure = present
  }

  # Dependency class

  if $dependency_class {
    include $dependency_class
  }

  # Resources managed

  if $package_name {
    package { 'network':
      ensure => $package_ensure,
      name   => $package_name,
    }
    Package['network'] -> Network::Interface<||>
    Package['network'] -> Network::Route<||>
    Package['network'] -> Network::Mroute<||>
    Package['network'] -> Network::Rule<||>
    Package['network'] -> Network::Routing_table<||>
  }

  if $config_file_path
  and $config_file_source
  or $manage_config_file_content {
    file { 'network.conf':
      ensure  => $config_file_ensure,
      path    => $config_file_path,
      mode    => $config_file_mode,
      owner   => $config_file_owner,
      group   => $config_file_group,
      source  => $config_file_source,
      content => $manage_config_file_content,
      notify  => $manage_config_file_notify,
      require => $config_file_require,
    }
  }

  if $config_dir_source {
    file { 'network.dir':
      ensure  => $config_dir_ensure,
      path    => $config_dir_path,
      source  => $config_dir_source,
      recurse => $config_dir_recurse,
      purge   => $config_dir_purge,
      force   => $config_dir_purge,
      notify  => $manage_config_file_notify,
      require => $config_file_require,
    }
  }

  # Command that triggers network restart
  exec { $service_restart_exec :
    command     => $service_restart_exec,
    alias       => 'network_restart',
    refreshonly => true,
    path        => '/bin:/sbin:/usr/bin:/usr/sbin',
  }

  # Create network interfaces from interfaces_hash, if present

  if $real_interfaces_hash {
    create_resources('network::interface', $real_interfaces_hash)
  }

  if $real_routes_hash {
    create_resources('network::route', $real_routes_hash)
  }

  if $real_mroutes_hash {
    create_resources('network::mroute', $real_mroutes_hash)
  }

  if $real_rules_hash {
    create_resources('network::rule', $real_rules_hash)
  }

  if $real_tables_hash {
    create_resources('network::routing_table', $real_tables_hash)
  }

  if $real_confs_hash {
    create_resources('network::conf', $real_confs_hash)
  }
  # Configure default gateway (On RedHat). Also hostname is set.
  if $facts['os']['family'] == 'RedHat'
  and ($network::gateway
  or $network::hostname) {
    file { '/etc/sysconfig/network':
      ensure  => $config_file_ensure,
      mode    => $config_file_mode,
      owner   => $config_file_owner,
      group   => $config_file_group,
      content => template($network::hostname_file_template),
      notify  => $network::manage_config_file_notify,
    }
    case $facts['os']['release']['major'] {
      '7','8': {
        exec { 'sethostname':
          command => "/usr/bin/hostnamectl set-hostname ${manage_hostname}",
          unless  => "/usr/bin/hostnamectl status | grep 'Static hostname: ${manage_hostname}'",
        }
      }
      default: {}
    }
  }

  # Configure hostname (On Debian)
  if $facts['os']['family'] == 'Debian'
  and $hostname {
    file { '/etc/hostname':
      ensure  => $config_file_ensure,
      mode    => $config_file_mode,
      owner   => $config_file_owner,
      group   => $config_file_group,
      content => template($hostname_file_template),
      notify  => $manage_config_file_notify,
    }
  }

  if $facts['os']['family'] == 'Suse' {
    if $hostname {
      file { '/etc/HOSTNAME':
        ensure  => $config_file_ensure,
        mode    => $config_file_mode,
        owner   => $config_file_owner,
        group   => $config_file_group,
        content => inline_template("<%= @manage_hostname %>\n"),
        notify  => Exec['sethostname'],
      }
      exec { 'sethostname':
        command => "/bin/hostname ${manage_hostname}",
        unless  => "/bin/hostname -f | grep ${manage_hostname}",
      }
    }
  }

  if $facts['os']['family'] == 'Solaris' {
    if $hostname {
      file { '/etc/nodename':
        ensure  => $config_file_ensure,
        mode    => $config_file_mode,
        owner   => $config_file_owner,
        group   => $config_file_group,
        content => inline_template("<%= @manage_hostname %>\n"),
        notify  => Exec['sethostname'],
      }
      exec { 'sethostname':
        command => "/usr/bin/hostname ${manage_hostname}",
        unless  => "/usr/bin/hostname | /usr/bin/grep ${manage_hostname}",
      }
    }
  }

  # Extra classes

  if $network::my_class {
    include $network::my_class
  }

  if $network::monitor_class {
    class { $network::monitor_class:
      options_hash => $network::monitor_options_hash,
      scope_hash   => {}, # TODO: Find a good way to inject class' scope
    }
  }

  if $firewall_class {
    class { $firewall_class:
      options_hash => $firewall_options_hash,
      scope_hash   => {},
    }
  }
}
