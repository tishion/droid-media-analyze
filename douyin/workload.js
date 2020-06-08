function replaceImplementation(methodName, overload) {
  overload.implementation = function() {
    console.log('+++++ ' + this.class.getName() + '.' + methodName);

    var ret = this[methodName].apply(this, arguments);

    console.log('----- ' + this.class.getName() + '.' + methodName);
    return ret;
  };
}

function hookMethod(classInstance, methodName) {
  console.log('  hooking method:', methodName);

  for (var i = 0; i < classInstance[methodName].overloads.length; i++) {
    console.log('    hooking overload:', i);
    replaceImplementation(methodName, classInstance[methodName].overloads[i]);
  }
}

function hookClassByInstance(classInstance) {
  console.log('Hooking class:' + classInstance.class.getName());
  var classMethods = classInstance.class.getDeclaredMethods();

  for (var i = 0; i < classMethods.length; i++) {
    var methodName = classMethods[i].getName();
    hookMethod(classInstance, methodName);
  }
}

function hookClassByName(clsName) {
  console.log('Hooking class:' + clsName);
  var classInstance = Java.use(clsName);
  hookClassByInstance(classInstance);
}

function hookClassMethod(clsName, methodName, hook) {
  var classInstance = Java.use(clsName);
  for (var i = 0; i < classInstance[methodName].overloads.length; i++) {
    console.log('    hooking overload:', i);

    classInstance[methodName].overloads[i].implementation = hook;
  }
}

if (Java.available) {
  Java.perform(function() {
    //hookClassByName('android.hardware.Camera');
    //hookClassByName('android.hardware.camera2.CameraDevice'); -- not used
    //hookClassByName('android.hardware.camera2.CameraCaptureSession'); -- not used

    // var classes = [
    //   'android.hardware.camera2.CameraManager',
    //   'android.hardware.camera2.CaptureRequest',
    //   'android.hardware.camera2.CameraCaptureSession',
    //   'android.media.MediaRecorder',
    //   'android.media.ImageReader',
    // ];

    // classes.forEach(function(c){
    //   hookClassByName(c);
    // });

    hookClassMethod('android.hardware.camera2.CameraManager', 'openCamera', function() {
      console.log('+++++ ' + this.class.getName() + '.openCamera');
      var cameraId = arguments[0];
      var stateCallback = arguments[1];
      console.log('camera id =', cameraId);
      hookClassByInstance(stateCallback);

      var ret = this['openCamera'].apply(this, arguments);
      console.log('----- ' + this.class.getName() + '.openCamera');
      return ret;
    });
  });
}