const { Worker } = require('worker_threads');
const path = require('path');
const os = require('os');

class WorkerPool {
  constructor(numWorkers = os.cpus().length) {
    this.numWorkers = numWorkers;
    this.workers = [];
    this.idleWorkers = [];
    this.taskQueue = [];
    this.callbacks = new Map();
    this.taskIdCounter = 0;

    for (let i = 0; i < this.numWorkers; i++) {
      this.addNewWorker();
    }
  }

  addNewWorker() {
    const worker = new Worker(path.join(__dirname, 'worker.js'));
    
    worker.on('message', (message) => {
      // Handle the message
      const isResult = message.success !== undefined; // Differentiate between log/result if needed
      
      if (isResult) {
        const { id, success, output, error } = message;
        // In the worker.js, it posts { id, success: true, result } or { id, success: false, error }
        // The destructuring above was slightly off in previous code I read?
        
        // Let's match what worker.js sends:
        // parentPort.postMessage({ id, success: true, result: scanResults });
        // parentPort.postMessage({ id, success: false, error: error.message });
        
        const result = message.result; // Extract result explicitly
        
        const callbackObj = this.callbacks.get(id);
        
        if (callbackObj) {
            this.callbacks.delete(id);
            if (success) {
                callbackObj.resolve(result);
            } else {
                callbackObj.reject(new Error(error));
            }
        }
        
        // Return worker to pool
        this.idleWorkers.push(worker);
        this.processNextTask();
      }
    });

    worker.on('error', (err) => {
      console.error('Worker error:', err);
      // Remove the worker and add a new one
      this.workers = this.workers.filter(w => w !== worker);
      this.idleWorkers = this.idleWorkers.filter(w => w !== worker);
      this.addNewWorker();
    });

    this.workers.push(worker);
    this.idleWorkers.push(worker);
  }

  processNextTask() {
    if (this.taskQueue.length === 0 || this.idleWorkers.length === 0) {
      return;
    }

    const task = this.taskQueue.shift();
    const worker = this.idleWorkers.shift();
    
    worker.postMessage(task.message);
  }

  runTask(buffer, options) {
    return new Promise((resolve, reject) => {
      const id = this.taskIdCounter++;
      this.callbacks.set(id, { resolve, reject });
      
      this.taskQueue.push({
        message: { id, buffer, options }
      });
      
      this.processNextTask();
    });
  }

  close() {
    for (const worker of this.workers) {
      worker.terminate();
    }
  }
}

// Create a singleton instance
const pool = new WorkerPool();

module.exports = pool;
