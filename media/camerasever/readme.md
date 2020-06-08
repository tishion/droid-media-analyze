Video

https://source.android.com/devices/camera

Apps(Frameworks)
    ⭣
Cameraserver(Process)
    FrameProcessorBase::processNewFrames 
        -> Camera3Device::getNextResult
        -> FrameProcessorBase::processSingleFrame -> FrameProcessorBase::processListeners -> (FilteredListener)CameraDeviceClient::onResultAvailable -> ICameraDeviceCallbacks::onResultAvailable -> TO APP Code;
    ⭣
Kernel(HAL)


https://cs.android.com/android/platform/superproject/+/master:frameworks/av/services/camera/libcameraservice/common/FrameProcessorBase.cpp;l=183;bpv=0;bpt=1


https://cs.android.com/android/platform/superproject/+/master:frameworks/av/services/camera/libcameraservice/device3/Camera3Device.cpp;l=2304;bpv=1;bpt=1

https://www.jianshu.com/p/3d88711a6911

_ZN7android13Camera3Device13getNextResultEPNS_13CaptureResultE
frida-trace -U -i "_ZN7android13Camera3Device13getNextResultEPNS_13CaptureResultE" cameraserver

