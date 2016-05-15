Pod::Spec.new do |s|
  s.name             = "Eclipse Mosquitto"
  s.version          = "1.4.8"
  s.summary          = "Eclipse Mosquitto is an open source implementation of a server for version 3.1 and 3.1.1 of the MQTT protocol."
  s.description      = "Eclipse Mosquitto is an open source implementation of a server for version 3.1 and 3.1.1 of the MQTT protocol."
  s.homepage         = "https://github.com/eclipse/mosquitto"
  s.license          = 'This project is dual licensed under the Eclipse Public License 1.0 and the Eclipse Distribution License 1.0 as described in the epl-v10 and edl-v10 files.'
  s.author           = { "Eclipse Foundation" => "emo@eclipse.org" }
  s.source           = { :git => "https://github.com/eclipse/mosquitto.git", :tag => "v1.4.8" }

  s.ios.deployment_target = '6.0'
  s.xcconfig = { 'HEADER_SEARCH_PATHS' => '${PODS_ROOT}/**', 
                 'CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES'  => 'YES',
                 'GCC_PREPROCESSOR_DEFINITIONS' => 'WITH_THREADING=1'
                }
  s.source_files = ['lib/*.{c,h}', '*.h']

  s.subspec 'WithoutTLS' do |sp|
    sp.source_files = ['lib/*.{c,h}', '*.h']
  end

  s.subspec 'TLS' do |sp|
    sp.xcconfig = { 'GCC_PREPROCESSOR_DEFINITIONS' => 'WITH_TLS=1' }
    sp.source_files = ['lib/*.{c,h}', '*.h']
    sp.dependency 'OpenSSL-Universal', '~> 1.0.1.19'
  end
  
end
