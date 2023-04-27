using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Windows.ApplicationModel.Core;
using Windows.Data.Xml.Dom;
using Windows.Security.Authentication.Identity.Provider;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.UI.Core;
using Windows.UI.Notifications;
using Windows.Devices.Bluetooth;
using Windows.Devices.Enumeration;
using System.Collections.ObjectModel;
using System.Diagnostics;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Navigation;
using Windows.Devices.Bluetooth.GenericAttributeProfile;


namespace Tasks
{
    public sealed class myBGTask : IBackgroundTask
    {
        private DeviceWatcher deviceWatcher;
        private List<string> deviceNames = new List<string>();
        Dictionary<string, string> deviceInfos = new Dictionary<string, string>();
        ManualResetEvent opCompletedEvent = null;
        public void Run(IBackgroundTaskInstance taskInstance)
        {
            var deferral = taskInstance.GetDeferral();

            // This event is signaled when the operation completes
            opCompletedEvent = new ManualResetEvent(false);
            SecondaryAuthenticationFactorAuthentication.AuthenticationStageChanged += OnStageChanged;
            ShowToastNotification("BG Task Hit!");

            // Wait until the operation completes
            opCompletedEvent.WaitOne();

            deferral.Complete();
        }

        async void PerformAuthentication()
        {
            ShowToastNotification("Performing Auth!");

            //Get the selected device from app settings
            var localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
            String m_selectedDeviceId = localSettings.Values["SelectedDevice"] as String;

            SecondaryAuthenticationFactorAuthenticationStageInfo authStageInfo = await SecondaryAuthenticationFactorAuthentication.GetAuthenticationStageInfoAsync();

            if (authStageInfo.Stage != SecondaryAuthenticationFactorAuthenticationStage.CollectingCredential)
            {
                ShowToastNotification("Unexpected!");
                throw new Exception("Unexpected!");
            }

            // ShowToastNotification("Post Collecting Credential");

            IReadOnlyList<SecondaryAuthenticationFactorInfo> deviceList = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(
                    SecondaryAuthenticationFactorDeviceFindScope.AllUsers);

            if (deviceList.Count == 0)
            {
                ShowToastNotification("Unexpected exception, device list = 0");
                throw new Exception("Unexpected exception, device list = 0");
            }

            // ShowToastNotification("Found companion devices");

            SecondaryAuthenticationFactorInfo deviceInfo = deviceList.ElementAt(0);
            m_selectedDeviceId = deviceInfo.DeviceId;

            // ShowToastNotification("Device ID: " + m_selectedDeviceId);

            //a nonce is an arbitrary number that may only be used once - a random or pseudo-random number issued in an authentication protocol to ensure that old communications cannot be reused in replay attacks.
            IBuffer svcNonce = CryptographicBuffer.GenerateRandom(32);  //Generate a nonce and do a HMAC operation with the nonce


            //In real world, you would need to take this nonce and send to companion device to perform an HMAC operation with it
            //You will have only 20 second to get the HMAC from the companion device
            SecondaryAuthenticationFactorAuthenticationResult authResult = await SecondaryAuthenticationFactorAuthentication.StartAuthenticationAsync(
                    m_selectedDeviceId, svcNonce);

            if (authResult.Status != SecondaryAuthenticationFactorAuthenticationStatus.Started)
            {
                ShowToastNotification("Unexpected! Could not start authentication!");
                throw new Exception("Unexpected! Could not start authentication!");
            }

            // ShowToastNotification("Auth Started");

            //
            // WARNING: Test code
            // The HAMC calculation SHOULD be done on companion device
            //
            byte[] combinedDataArray;
            CryptographicBuffer.CopyToByteArray(authResult.Authentication.DeviceConfigurationData, out combinedDataArray);

            byte[] deviceKeyArray = new byte[32];
            byte[] authKeyArray = new byte[32];
            for (int index = 0; index < deviceKeyArray.Length; index++)
            {
                deviceKeyArray[index] = combinedDataArray[index];
            }
            for (int index = 0; index < authKeyArray.Length; index++)
            {
                authKeyArray[index] = combinedDataArray[deviceKeyArray.Length + index];
            }
            // Create device key and authentication key
            IBuffer deviceKey = CryptographicBuffer.CreateFromByteArray(deviceKeyArray);
            IBuffer authKey = CryptographicBuffer.CreateFromByteArray(authKeyArray);

            // Calculate the HMAC
            MacAlgorithmProvider hMACSha256Provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);

            CryptographicKey deviceHmacKey = hMACSha256Provider.CreateKey(deviceKey);
            IBuffer deviceHmac = CryptographicEngine.Sign(deviceHmacKey, authResult.Authentication.DeviceNonce);

            // sessionHmac = HMAC(authKey, deviceHmac || sessionNonce)
            IBuffer sessionHmac;
            byte[] deviceHmacArray = { 0 };
            CryptographicBuffer.CopyToByteArray(deviceHmac, out deviceHmacArray);

            byte[] sessionNonceArray = { 0 };
            CryptographicBuffer.CopyToByteArray(authResult.Authentication.SessionNonce, out sessionNonceArray);

            combinedDataArray = new byte[deviceHmacArray.Length + sessionNonceArray.Length];
            for (int index = 0; index < deviceHmacArray.Length; index++)
            {
                combinedDataArray[index] = deviceHmacArray[index];
            }
            for (int index = 0; index < sessionNonceArray.Length; index++)
            {
                combinedDataArray[deviceHmacArray.Length + index] = sessionNonceArray[index];
            }

            // Get a Ibuffer from combinedDataArray
            IBuffer sessionMessage = CryptographicBuffer.CreateFromByteArray(combinedDataArray);

            // Calculate sessionHmac
            CryptographicKey authHmacKey = hMACSha256Provider.CreateKey(authKey);
            sessionHmac = CryptographicEngine.Sign(authHmacKey, sessionMessage);

            // ShowToastNotification("Before finish auth");

            SecondaryAuthenticationFactorFinishAuthenticationStatus authStatus = await authResult.Authentication.FinishAuthenticationAsync(deviceHmac,
                sessionHmac);

            if (authStatus != SecondaryAuthenticationFactorFinishAuthenticationStatus.Completed)
            {
                ShowToastNotification("Unable to complete authentication!");
                throw new Exception("Unable to complete authentication!");
            }

            // ShowToastNotification("Auth completed");
        }

        public static void ShowToastNotification(string message)
        {

            ToastTemplateType toastTemplate = ToastTemplateType.ToastImageAndText01;
            XmlDocument toastXml = ToastNotificationManager.GetTemplateContent(toastTemplate);

            // Set Text
            XmlNodeList toastTextElements = toastXml.GetElementsByTagName("text");
            toastTextElements[0].AppendChild(toastXml.CreateTextNode(message));

            // Set image
            // Images must be less than 200 KB in size and smaller than 1024 x 1024 pixels.
            XmlNodeList toastImageAttributes = toastXml.GetElementsByTagName("image");
            ((XmlElement)toastImageAttributes[0]).SetAttribute("src", "ms-appx:///Images/logo-80px-80px.png");
            ((XmlElement)toastImageAttributes[0]).SetAttribute("alt", "logo");

            // toast duration
            IXmlNode toastNode = toastXml.SelectSingleNode("/toast");
            ((XmlElement)toastNode).SetAttribute("duration", "short");

            // toast navigation
            var toastNavigationUriString = "#/MainPage.xaml?param1=12345";
            var toastElement = ((XmlElement)toastXml.SelectSingleNode("/toast"));
            toastElement.SetAttribute("launch", toastNavigationUriString);

            // Create the toast notification based on the XML content you've specified.
            ToastNotification toast = new ToastNotification(toastXml);

            // Send your toast notification.
            ToastNotificationManager.CreateToastNotifier().Show(toast);

        }

        async void OnStageChanged(Object sender, SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs args)
        {
            // ShowToastNotification("In StageChanged!" + args.StageInfo.Stage.ToString());
            if (args.StageInfo.Stage == SecondaryAuthenticationFactorAuthenticationStage.WaitingForUserConfirmation)
            {
                // ShowToastNotification("Stage = WaitingForUserConfirmation");
                // This event is happening on a ThreadPool thread, so we need to dispatch to the UI thread.
                // Getting the dispatcher from the MainView works as long as we only have one view.
                String deviceName = "DeviceSimulator.";
                await SecondaryAuthenticationFactorAuthentication.ShowNotificationMessageAsync(
                    deviceName,
                    SecondaryAuthenticationFactorAuthenticationMessage.SwipeUpWelcome);
            }
            else if (args.StageInfo.Stage == SecondaryAuthenticationFactorAuthenticationStage.CollectingCredential)
            {
                // ShowToastNotification("Stage = CollectingCredential");

                await CheckDeivce();
                PerformAuthentication();
            }
            else
            {
                if (args.StageInfo.Stage == SecondaryAuthenticationFactorAuthenticationStage.StoppingAuthentication)
                {
                    SecondaryAuthenticationFactorAuthentication.AuthenticationStageChanged -= OnStageChanged;
                    StopBleDeviceWatcher();
                    opCompletedEvent.Set();
                }

                SecondaryAuthenticationFactorAuthenticationStage stage = args.StageInfo.Stage;
            }
        }
        async Task CheckDeivce()
        {
            if (await CheckDeivceConnected())
                return;
            StartBleDeviceWatcher();
            while (true)
            {
                await Task.Delay(TimeSpan.FromSeconds(1));
                foreach (string id in deviceInfos.Keys)
                {
                    ShowToastNotification(id);
                    ShowToastNotification(deviceInfos[id]);
                }

                foreach (string id in deviceInfos.Keys)
                {
                    if (deviceInfos[id] == "那只猫的se")
                    {
                        ShowToastNotification("found se");
                        BluetoothLEDevice bluetoothLeDevice = null;
                        bluetoothLeDevice = await BluetoothLEDevice.FromIdAsync(id);
                        if (bluetoothLeDevice == null)
                            ShowToastNotification("Failed to connect to device.");
                        else
                        {
                            GattDeviceServicesResult result = await bluetoothLeDevice.GetGattServicesAsync(BluetoothCacheMode.Uncached);
                            if (result.Status == GattCommunicationStatus.Success)
                                return;
                            else
                                ShowToastNotification("result.Status " + result.Status);
                        }
                    }
                }
            }
        }
        private void StartBleDeviceWatcher()
        {
            string[] requestedProperties = { "System.Devices.Aep.DeviceAddress", "System.Devices.Aep.IsConnected", "System.Devices.Aep.Bluetooth.Le.IsConnectable" };

            string aqsAllBluetoothLEDevices = "(System.Devices.Aep.ProtocolId:=\"{bb7bb05e-5972-42b5-94fc-76eaa7084d49}\")";

            deviceWatcher =
                    DeviceInformation.CreateWatcher(
                        aqsAllBluetoothLEDevices,
                        requestedProperties,
                        DeviceInformationKind.AssociationEndpoint);

            deviceWatcher.Added += DeviceWatcher_Added;
            deviceNames.Clear();
            deviceWatcher.Start();
        }
        private void StopBleDeviceWatcher()
        {
            if (deviceWatcher != null)
            {
                deviceWatcher.Added -= DeviceWatcher_Added;
                deviceWatcher.Stop();
                deviceWatcher = null;
            }
        }

        private void DeviceWatcher_Added(DeviceWatcher sender, DeviceInformation deviceInfo)
        {
            deviceNames.Add(deviceInfo.Name);
            deviceInfos[deviceInfo.Id] = deviceInfo.Name;
        }

        async Task<bool> CheckDeivceConnected()
        {
            var allPairedDevices = await DeviceInformation.FindAllAsync(BluetoothDevice.GetDeviceSelectorFromPairingState(true));
            ShowToastNotification(allPairedDevices.Count().ToString());
            foreach (var device in allPairedDevices)
            {
                var bluetoothDevice = await BluetoothDevice.FromIdAsync(device.Id);
                var connectionStatus = bluetoothDevice.ConnectionStatus.ToString();
                ShowToastNotification(device.Name + " " + connectionStatus);
                if (device.Name == "那只猫的se" && connectionStatus == "Connected")
                {
                    ShowToastNotification("found se 309");
                    return true;
                }
            }
            return false;
        }
    }

}
