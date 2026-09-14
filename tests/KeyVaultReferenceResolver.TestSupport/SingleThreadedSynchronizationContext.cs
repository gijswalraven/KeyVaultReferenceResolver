using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace KeyVaultReferenceResolver.Testing
{
    /// <summary>
    /// A <see cref="SynchronizationContext"/> that posts every continuation back to a single
    /// pumping thread, the way classic ASP.NET, WPF and WinForms do.
    /// </summary>
    /// <remarks>
    /// Blocking that thread while waiting for work whose continuation is queued to it is what
    /// deadlocks. <see cref="Run"/> installs the context, runs the work on the pumping thread and
    /// fails with a <see cref="TimeoutException"/> rather than hanging the test run forever.
    /// </remarks>
    public sealed class SingleThreadedSynchronizationContext : SynchronizationContext, IDisposable
    {
        private readonly BlockingCollection<(SendOrPostCallback Callback, object? State)> _queue = new();
        private readonly Thread _thread;

        /// <summary>
        /// Starts the pumping thread.
        /// </summary>
        public SingleThreadedSynchronizationContext()
        {
            _thread = new Thread(Pump) { IsBackground = true, Name = "sync-context-pump" };
            _thread.Start();
        }

        /// <inheritdoc />
        public override void Post(SendOrPostCallback d, object? state)
        {
            if (!_queue.IsAddingCompleted)
                _queue.Add((d, state));
        }

        /// <inheritdoc />
        public override void Send(SendOrPostCallback d, object? state)
        {
            ArgumentNullException.ThrowIfNull(d);
            d(state);
        }

        /// <summary>
        /// Runs <paramref name="work"/> on the pumping thread with this context installed.
        /// </summary>
        /// <typeparam name="T">The result type.</typeparam>
        /// <param name="work">The work to run.</param>
        /// <param name="timeout">How long to wait before declaring a deadlock. Default 30 seconds.</param>
        /// <returns>The result of <paramref name="work"/>.</returns>
        /// <exception cref="TimeoutException">Thrown when the work does not complete in time.</exception>
        public T Run<T>(Func<T> work, TimeSpan? timeout = null)
        {
            ArgumentNullException.ThrowIfNull(work);

            var completion = new TaskCompletionSource<T>();

            Post(_ =>
            {
                try
                {
                    completion.SetResult(work());
                }
                catch (Exception ex)
                {
                    completion.SetException(ex);
                }
            }, null);

            if (!completion.Task.Wait(timeout ?? TimeSpan.FromSeconds(30)))
                throw new TimeoutException("The work deadlocked under a SynchronizationContext.");

            return completion.Task.Result;
        }

        /// <summary>
        /// Stops the pumping thread.
        /// </summary>
        public void Dispose()
        {
            _queue.CompleteAdding();
            _thread.Join(TimeSpan.FromSeconds(5));
            _queue.Dispose();
        }

        private void Pump()
        {
            SetSynchronizationContext(this);

            foreach (var (callback, state) in _queue.GetConsumingEnumerable())
                callback(state);
        }
    }
}
