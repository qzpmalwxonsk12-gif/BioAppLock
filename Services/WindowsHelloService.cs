using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace BioAppLock.Services
{
    public enum HelloAvailability
    {
        Available = 0,
        DeviceNotPresent = 1,
        NotConfiguredForUser = 2,
        DisabledByPolicy = 3,
        DeviceBusy = 4,
        Unknown = 99
    }

    public enum HelloVerificationResult
    {
        Verified = 0,
        DeviceNotPresent = 1,
        NotConfiguredForUser = 2,
        DisabledByPolicy = 3,
        DeviceBusy = 4,
        RetriesExhausted = 5,
        Canceled = 6,
        Error = 99
    }

    public static class WindowsHelloService
    {
        private const string RuntimeClassName = "Windows.Security.Credentials.UI.UserConsentVerifier";

        private static Guid IID_IUserConsentVerifierStatics = new("af4f3f91-564c-4ddc-b8b5-973447627c65");
        private static Guid IID_IUserConsentVerifierInterop = new("39E050C3-4E74-441A-8DC0-B81104DF949C");
        private static Guid IID_IAsyncInfo = new("00000036-0000-0000-C000-000000000046");
        private static Guid IID_IAsyncOpVerificationResult = new("fd596ffd-2318-558f-9dbe-d21df43764a5");
        private static Guid IID_IAsyncOpAvailability = new("ddd384f3-d818-5d83-ab4b-32119c28587c");

        [DllImport("combase.dll", PreserveSig = true)]
        private static extern int RoInitialize(int initType);

        [DllImport("combase.dll", PreserveSig = true)]
        private static extern int RoGetActivationFactory(
            IntPtr activatableClassId,
            ref Guid iid,
            out IntPtr factory);

        [DllImport("combase.dll", PreserveSig = true, CharSet = CharSet.Unicode)]
        private static extern int WindowsCreateString(
            string sourceString,
            uint length,
            out IntPtr hstring);

        [DllImport("combase.dll", PreserveSig = true)]
        private static extern int WindowsDeleteString(IntPtr hstring);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int CheckAvailabilityAsyncDelegate(IntPtr thisPtr, out IntPtr asyncOp);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int RequestVerificationAsyncDelegate(IntPtr thisPtr, IntPtr messageHString, out IntPtr asyncOp);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int RequestVerificationForWindowAsyncDelegate(
            IntPtr thisPtr,
            IntPtr appWindow,
            IntPtr messageHString,
            ref Guid riid,
            out IntPtr asyncOp);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int GetStatusDelegate(IntPtr thisPtr, out int status);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int CancelDelegate(IntPtr thisPtr);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int CloseDelegate(IntPtr thisPtr);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int GetResultsDelegate(IntPtr thisPtr, out int result);

        public static async Task<HelloAvailability> CheckAvailabilityAsync()
        {
            IntPtr hClassId = IntPtr.Zero;
            IntPtr factory = IntPtr.Zero;
            IntPtr asyncOp = IntPtr.Zero;

            try
            {
                RoInitialize(1);

                int hr = WindowsCreateString(RuntimeClassName, (uint)RuntimeClassName.Length, out hClassId);
                if (hr < 0) return HelloAvailability.Unknown;

                hr = RoGetActivationFactory(hClassId, ref IID_IUserConsentVerifierStatics, out factory);
                if (hr < 0 || factory == IntPtr.Zero) return HelloAvailability.Unknown;

                IntPtr vtable = Marshal.ReadIntPtr(factory);
                IntPtr methodPtr = Marshal.ReadIntPtr(vtable, 6 * IntPtr.Size);
                var checkFn = Marshal.GetDelegateForFunctionPointer<CheckAvailabilityAsyncDelegate>(methodPtr);

                hr = checkFn(factory, out asyncOp);
                if (hr < 0 || asyncOp == IntPtr.Zero) return HelloAvailability.Unknown;

                int rawResult = await AwaitWinRtEnumOperationAsync(asyncOp, enforceCredentialFocus: false, null, CancellationToken.None);
                if (rawResult >= 0 && rawResult <= 4)
                    return (HelloAvailability)rawResult;

                return HelloAvailability.Unknown;
            }
            catch
            {
                return HelloAvailability.Unknown;
            }
            finally
            {
                if (asyncOp != IntPtr.Zero) Marshal.Release(asyncOp);
                if (factory != IntPtr.Zero) Marshal.Release(factory);
                if (hClassId != IntPtr.Zero) WindowsDeleteString(hClassId);
            }
        }

        /// <summary>
        /// Triggers the native Windows Security (Windows Hello Fingerprint / PIN) dialog,
        /// ensuring the owner window holds the foreground token before launch and keeping CredentialUIBroker.exe
        /// actively focused so Windows Biometric Service (WbioSrvc) always routes fingerprint sensor touches to it.
        /// </summary>
        public static async Task<HelloVerificationResult> RequestVerificationAsync(
            IntPtr ownerWindowHandle,
            string message,
            CancellationToken cancellationToken = default,
            Func<bool>? shouldEnforceFocus = null)
        {
            // Automatically retry if WbioSrvc briefly reports DeviceBusy from a prior prompt closing
            for (int attempt = 0; attempt < 3; attempt++)
            {
                if (cancellationToken.IsCancellationRequested)
                    return HelloVerificationResult.Canceled;

                var res = await RequestVerificationInternalAsync(
                    ownerWindowHandle,
                    message,
                    cancellationToken,
                    shouldEnforceFocus);

                if (res != HelloVerificationResult.DeviceBusy)
                    return res;

                await Task.Delay(300, CancellationToken.None);
            }

            return HelloVerificationResult.DeviceBusy;
        }

        private static async Task<HelloVerificationResult> RequestVerificationInternalAsync(
            IntPtr ownerWindowHandle,
            string message,
            CancellationToken cancellationToken,
            Func<bool>? shouldEnforceFocus)
        {
            IntPtr hClassId = IntPtr.Zero;
            IntPtr hMessage = IntPtr.Zero;
            IntPtr interopFactory = IntPtr.Zero;
            IntPtr staticsFactory = IntPtr.Zero;
            IntPtr asyncOp = IntPtr.Zero;

            try
            {
                RoInitialize(1);

                // Critical for Windows Biometric Service (WbioSrvc):
                // Ensure our owner window actually holds the Win32 foreground lock right before
                // calling RequestVerificationForWindowAsync so Windows grants CredentialUIBroker foreground focus!
                if (ownerWindowHandle != IntPtr.Zero)
                {
                    Win32Api.ForceRestoreAndFocusWindow(ownerWindowHandle);
                    await Task.Delay(40, CancellationToken.None);
                }

                int hr = WindowsCreateString(RuntimeClassName, (uint)RuntimeClassName.Length, out hClassId);
                if (hr < 0) return HelloVerificationResult.Error;

                hr = WindowsCreateString(message, (uint)message.Length, out hMessage);
                if (hr < 0) return HelloVerificationResult.Error;

                if (ownerWindowHandle != IntPtr.Zero)
                {
                    hr = RoGetActivationFactory(hClassId, ref IID_IUserConsentVerifierInterop, out interopFactory);
                    if (hr >= 0 && interopFactory != IntPtr.Zero)
                    {
                        IntPtr vtable = Marshal.ReadIntPtr(interopFactory);
                        IntPtr methodPtr = Marshal.ReadIntPtr(vtable, 6 * IntPtr.Size);
                        var reqForWindowFn = Marshal.GetDelegateForFunctionPointer<RequestVerificationForWindowAsyncDelegate>(methodPtr);

                        Guid riid = IID_IAsyncOpVerificationResult;
                        hr = reqForWindowFn(interopFactory, ownerWindowHandle, hMessage, ref riid, out asyncOp);
                    }
                }

                if (asyncOp == IntPtr.Zero)
                {
                    hr = RoGetActivationFactory(hClassId, ref IID_IUserConsentVerifierStatics, out staticsFactory);
                    if (hr >= 0 && staticsFactory != IntPtr.Zero)
                    {
                        IntPtr vtable = Marshal.ReadIntPtr(staticsFactory);
                        IntPtr methodPtr = Marshal.ReadIntPtr(vtable, 7 * IntPtr.Size);
                        var reqFn = Marshal.GetDelegateForFunctionPointer<RequestVerificationAsyncDelegate>(methodPtr);
                        hr = reqFn(staticsFactory, hMessage, out asyncOp);
                    }
                }

                if (asyncOp == IntPtr.Zero)
                {
                    return await FallbackPowerShellVerificationAsync(message, cancellationToken);
                }

                int rawResult = await AwaitWinRtEnumOperationAsync(
                    asyncOp,
                    enforceCredentialFocus: true,
                    shouldEnforceFocus,
                    cancellationToken);

                if (rawResult >= 0 && rawResult <= 6)
                {
                    return (HelloVerificationResult)rawResult;
                }

                return HelloVerificationResult.Canceled;
            }
            catch
            {
                return HelloVerificationResult.Error;
            }
            finally
            {
                if (asyncOp != IntPtr.Zero) Marshal.Release(asyncOp);
                if (interopFactory != IntPtr.Zero) Marshal.Release(interopFactory);
                if (staticsFactory != IntPtr.Zero) Marshal.Release(staticsFactory);
                if (hMessage != IntPtr.Zero) WindowsDeleteString(hMessage);
                if (hClassId != IntPtr.Zero) WindowsDeleteString(hClassId);
            }
        }

        private static async Task<int> AwaitWinRtEnumOperationAsync(
            IntPtr asyncOp,
            bool enforceCredentialFocus,
            Func<bool>? shouldEnforceFocus,
            CancellationToken cancellationToken)
        {
            IntPtr asyncInfo = IntPtr.Zero;
            try
            {
                int hr = Marshal.QueryInterface(asyncOp, in IID_IAsyncInfo, out asyncInfo);
                if (hr < 0 || asyncInfo == IntPtr.Zero) return -1;

                IntPtr infoVtable = Marshal.ReadIntPtr(asyncInfo);
                // IAsyncInfo: 6=get_Id, 7=get_Status, 8=get_ErrorCode, 9=Cancel, 10=Close
                IntPtr getStatusPtr = Marshal.ReadIntPtr(infoVtable, 7 * IntPtr.Size);
                IntPtr cancelPtr = Marshal.ReadIntPtr(infoVtable, 9 * IntPtr.Size);
                IntPtr closePtr = Marshal.ReadIntPtr(infoVtable, 10 * IntPtr.Size);
                var getStatusFn = Marshal.GetDelegateForFunctionPointer<GetStatusDelegate>(getStatusPtr);
                var cancelFn = Marshal.GetDelegateForFunctionPointer<CancelDelegate>(cancelPtr);
                var closeFn = Marshal.GetDelegateForFunctionPointer<CloseDelegate>(closePtr);

                int tickCount = 0;
                bool initialCredFocusApplied = false;

                while (true)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        cancelFn(asyncInfo);
                        closeFn(asyncInfo);
                        return (int)HelloVerificationResult.Canceled;
                    }

                    hr = getStatusFn(asyncInfo, out int status);
                    if (hr < 0) return -1;

                    // AsyncStatus: 0 = Started, 1 = Completed, 2 = Canceled, 3 = Error
                    if (status != 0)
                    {
                        if (status == 2) return (int)HelloVerificationResult.Canceled;
                        if (status == 3) return -1;
                        break;
                    }

                    // Keep CredentialUIBroker.exe as the active foreground window so WbioSrvc
                    // routes fingerprint sensor input to it without requiring a manual mouse click.
                    if (enforceCredentialFocus && (tickCount % 2 == 0))
                    {
                        bool allowFocus = shouldEnforceFocus == null || shouldEnforceFocus();
                        if (allowFocus)
                        {
                            IntPtr credHwnd = Win32Api.FindCredentialUiWindow();
                            if (credHwnd != IntPtr.Zero)
                            {
                                if (!initialCredFocusApplied || Win32Api.GetForegroundWindow() != credHwnd)
                                {
                                    Win32Api.ForceFocusCredentialWindow(credHwnd);
                                    initialCredFocusApplied = true;
                                }
                            }
                        }
                    }

                    tickCount++;
                    await Task.Delay(35, CancellationToken.None);
                }

                // IAsyncOperation<T>: 6=put_Completed, 7=get_Completed, 8=GetResults
                IntPtr opVtable = Marshal.ReadIntPtr(asyncOp);
                IntPtr getResultsPtr = Marshal.ReadIntPtr(opVtable, 8 * IntPtr.Size);
                var getResultsFn = Marshal.GetDelegateForFunctionPointer<GetResultsDelegate>(getResultsPtr);

                hr = getResultsFn(asyncOp, out int resultValue);
                closeFn(asyncInfo);
                if (hr < 0) return -1;
                return resultValue;
            }
            finally
            {
                if (asyncInfo != IntPtr.Zero) Marshal.Release(asyncInfo);
            }
        }

        private static async Task<HelloVerificationResult> FallbackPowerShellVerificationAsync(
            string message,
            CancellationToken cancellationToken)
        {
            try
            {
                string safeMsg = message.Replace("'", "''");
                string script = $@"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {{ $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' }})[0]
Function Await($WinRtTask, $ResultType) {{
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}}
[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null
$res = Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('{safeMsg}')) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])
Write-Output $res
";
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -WindowStyle Hidden -Command \"{script}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return HelloVerificationResult.Error;
                string output = await proc.StandardOutput.ReadToEndAsync(cancellationToken);
                await proc.WaitForExitAsync(cancellationToken);

                if (Enum.TryParse<HelloVerificationResult>(output.Trim(), true, out var parsed))
                {
                    return parsed;
                }
                return HelloVerificationResult.Canceled;
            }
            catch
            {
                return HelloVerificationResult.Error;
            }
        }
    }
}
