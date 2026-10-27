using System.Diagnostics;

namespace Guardian;

static class Program
{
    private const string AppGuid = "Global\\Guardian_Security_Personal_Laptop_Guard_App";
    private const string ShowEventName = "Global\\Guardian_Show_Window_Event";
    private static Mutex? _mutex;
    private static EventWaitHandle? _showEvent;

    [STAThread]
    static void Main()
    {
        _mutex = new Mutex(true, AppGuid, out bool createdNew);

        if (!createdNew)
        {
            // Another instance is already running! Signal it to restore/show its window!
            try
            {
                if (EventWaitHandle.TryOpenExisting(ShowEventName, out var existingEvent))
                {
                    existingEvent.Set();
                }
            }
            catch { }
            return;
        }

        // Create the event listener so secondary launches can wake this instance
        try
        {
            _showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        }
        catch { }

        ApplicationConfiguration.Initialize();
        var mainForm = new MainForm(_showEvent);
        Application.Run(mainForm);

        GC.KeepAlive(_mutex);
        GC.KeepAlive(_showEvent);
    }
}