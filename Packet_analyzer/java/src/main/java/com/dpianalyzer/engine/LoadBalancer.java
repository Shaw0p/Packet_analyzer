package com.dpianalyzer.engine;

import com.dpianalyzer.model.PacketJob;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Load Balancer thread that distributes packets across Fast Path threads based on consistent FiveTuple hashing.
 */
public class LoadBalancer implements Runnable {
    private final int lbId;
    private final List<FastPathProcessor> fps;
    private final int numFps;
    private final BlockingQueue<PacketJob> inputQueue = new LinkedBlockingQueue<>(10000);

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread workerThread;
    private final AtomicLong dispatched = new AtomicLong(0);

    public LoadBalancer(int lbId, List<FastPathProcessor> fps) {
        this.lbId = lbId;
        this.fps = fps;
        this.numFps = fps.size();
    }

    public void start() {
        if (running.compareAndSet(false, true)) {
            workerThread = new Thread(this, "LoadBalancer-" + lbId);
            workerThread.start();
            System.out.println("[LB" + lbId + "] Started (serving " + numFps + " FPs)");
        }
    }

    public void stop() {
        if (running.compareAndSet(true, false)) {
            if (workerThread != null) {
                try {
                    workerThread.join(2000);
                } catch (InterruptedException ignored) {}
            }
            System.out.println("[LB" + lbId + "] Stopped");
        }
    }

    public BlockingQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public long getDispatched() {
        return dispatched.get();
    }

    @Override
    public void run() {
        while (running.get() || !inputQueue.isEmpty()) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) continue;

                int hash = job.getTuple().hashCode() & 0x7FFFFFFF;
                int fpIndex = hash % numFps;

                fps.get(fpIndex).getInputQueue().put(job);
                dispatched.incrementAndGet();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                System.err.println("[LB" + lbId + "] Error dispatching packet: " + e.getMessage());
            }
        }
    }
}
