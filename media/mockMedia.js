/**
 *
 * The script to intercept the xCloud game streaming application.
 *
 * Sheen Tian @ 2019-11-21-13:24:12
 */

/**
 * Intercepts the function at the given address
 * @param {The address to be intercept} address
 * @param {The export information} e
 */
function intercept(address, e) {
    try {
        if (e.replace != undefined) {
            Interceptor.replace(address, e.replace);
        } else if (e.attach != undefined) {
            Interceptor.attach(address, e.attach);
        } else {
            console.error('No interception mode specified');
        }
    } catch (exp) {
        console.error(
            'Failed to intercept the export: ' + e.name + ', error: ' + exp);
    }
}

/**
 * Processes the exprot
 * @param {The module information} m
 * @param {The export information} e
 */
function process_export(m, e) {
    if (e.skip) {
        console.log('     !!!! Export skipped: ' + e.name);
        return;
    }
    try {
        var address = Module.findExportByName(m.name, e.symbol);
        if (address != null) {
            intercept(address, e);
            console.log('     **** Hook ' + e.name + ' @ ' + address);
        } else {
            console.error('     !!!! Export not found: ' + e.name);
        }
    } catch (exp) {
        console.error(
            '     !!!! Failed to find the export: ' + e.name + ', error: ' + exp);
    }
}

/**
 * Processes the module
 * @param {The module list} modules
 */
function do_hook(modules) {
    modules.forEach(function (m) {
        if (m.skip) {
            console.log('==== Module skipped: ' + m.name);
            return;
        }
        console.log('++++ Module ' + m.name);
        m.exports.forEach(function (e) {
            process_export(m, e);
        });
        console.log('---- Module ' + m.name);
    });
}

function do_init() { }

/**
 * The module list
 */
var MODULES = [
    {
        name: 'libaaudio.so',
        skip: false,
        exports: [
            {
                symbol: '_ZN7android11ServerProxy12obtainBufferEPNS_5Proxy6BufferEb',
                name: 'android::ServerProxy::obtainBuffer()',
                skip: false,
                attach: {
                    onEnter: function (args) {
                        var This = args[0];
                        var buffer = args[1];
                        var ackFlush = args[2];
                        console.log(
                            'android::ServerProxy::obtainBuffer() called with args:',
                            args[0], args[1], args[2]);
                    },
                    onLeave: function (ret) { }
                }
            },
        ]
    },
    {
        name: 'libcameraservice.so',
        skip: false,
        exports: [
            {
                symbol: '_ZN7android13Camera3Device13getNextResultEPNS_13CaptureResultE',
                name: 'android::Camera3Device::getNextResult(CaptureResult *frame)',
                skip: true,
                replace: new NativeCallback(
                    function (This, result) {
                        console.log(
                            'android::Camera3Device::getNextResult called:', This,
                            result);
                        return 0;
                    },
                    'int', ['pointer', 'pointer']),
                attach: {
                    onEnter: function (args) {
                        var This = args[0];
                        var captureResult = args[1];
                        console.log(
                            'android::Camera3Device::getNextResult called:', args[0],
                            args[1]);
                    },
                    onLeave: function (ret) {
                        ret.replace(-1);
                    }
                }
            },
            {
                symbol: '_ZN7android13Camera3Device19returnOutputBuffersEPK21camera3_stream_bufferjx',
                name: 'android::Camera3Device::returnOutputBuffers(' +
                    'const camera3_stream_buffer_t *outputBuffers, ' +
                    'size_t numBuffers, ' +
                    'nsecs_t timestamp)',
                skip: false,
                // replace: new NativeCallback(
                //     function (
                //         This, outputBuffers, numBuffers, timestamp) {
                //         console.log(
                //             'android::Camera3Device::returnOutputBuffers called:',
                //             This, outputBuffers, numBuffers, timestamp);
                //     },
                //     'void',
                //     ['pointer', 'pointer', 'uint32', 'int64']),
                attach: {
                    onEnter: function (args) {
                        console.log('Context  : ' + JSON.stringify(this, null, 2));
                        console.log('Return   : ' + this.returnAddress);
                        console.log('ThreadId : ' + this.threadId);
                        console.log('Depth    : ' + this.depth);
                        console.log('Errornr  : ' + this.err);

                        var This = args[0];
                        var outputBuffers = args[1];
                        var numBuffers = args[2]
                        var timestamp = args[3];

                        console.log(
                            'android::Camera3Device::returnOutputBuffers called:',
                            This, outputBuffers, numBuffers, timestamp
                        );
                    },
                    onLeave: function (ret) { }
                }
            }
        ]
    },
];


function entry() {
    // do_init();
    // do_hook(MODULES);

    var returnOutputBuffers_addr = Module.findExportByName(
        'libcameraservice.so',
        '_ZN7android13Camera3Device19returnOutputBuffersEPK21camera3_stream_bufferjx'
    )

    var org_returnOutputBuffers = new NativeFunction(
        returnOutputBuffers_addr,
        'void', ['pointer', 'pointer', 'uint32', 'int64']
    );

    Interceptor.replace(returnOutputBuffers_addr, new NativeCallback(
        function (This, outputBuffers, numBuffers, timestamp) {
            console.log(
                'android::Camera3Device::returnOutputBuffers called:',
                This, outputBuffers, numBuffers, timestamp);

            return org_returnOutputBuffers(
                This,
                outputBuffers,
                numBuffers,
                0
            );
        },
        'void',
        ['pointer', 'pointer', 'uint32', 'int64'])
    );
}

if (Java.available) {
    Java.perform(entry);
} else {
    entry();
}