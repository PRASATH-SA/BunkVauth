class BehavioralCollector {
    constructor() {
        this.buffer = [];
        this.limit = 1000;
        this.keyDepressTimes = {};
        this.lastKeyUpTime = null;
        this.mouseEvents = [];
        this.isRunning = false;
    }

    start() {
        if (this.isRunning) return;
        this.isRunning = true;
        
        window.addEventListener('keydown', (e) => this.handleKeyDown(e));
        window.addEventListener('keyup', (e) => this.handleKeyUp(e));
        window.addEventListener('mousemove', (e) => this.handleMouseMove(e));
        window.addEventListener('click', (e) => this.handleClick(e));

        setInterval(() => this.sendData(), 5000);
        console.log("BunkVauth Behavioral Collector Active");
    }

    handleKeyDown(e) {
        if (!this.keyDepressTimes[e.key]) {
            this.keyDepressTimes[e.key] = Date.now();
        }
    }

    handleKeyUp(e) {
        const now = Date.now();
        const start = this.keyDepressTimes[e.key];
        if (start) {
            const dwellTime = now - start;
            const flightTime = this.lastKeyUpTime ? now - this.lastKeyUpTime : 0;
            this.buffer.push({type: 'keystroke', key: e.key, dwell: dwellTime, flight: flightTime, ts: now});
            this.lastKeyUpTime = now;
            delete this.keyDepressTimes[e.key];
        }
    }

    handleMouseMove(e) {
        this.mouseEvents.push({x: e.clientX, y: e.clientY, ts: Date.now()});
        if (this.mouseEvents.length > 100) this.mouseEvents.shift();
    }

    handleClick(e) {
        this.buffer.push({type: 'click', x: e.clientX, y: e.clientY, ts: Date.now()});
    }

    calculateFeatures() {
        const keystrokes = this.buffer.filter(e => e.type === 'keystroke');
        if (keystrokes.length < 5) return null;

        const dwells = keystrokes.map(k => k.dwell);
        const flights = keystrokes.map(k => k.flight).filter(f => f > 0);
        const avg = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
        const std = (arr, mean) => Math.sqrt(arr.map(x => Math.pow(x - mean, 2)).reduce((a, b) => a + b, 0) / arr.length);

        const avgDwell = avg(dwells);
        const avgFlight = flights.length ? avg(flights) : 0;

        let totalDist = 0;
        for (let i = 1; i < this.mouseEvents.length; i++) {
            totalDist += Math.sqrt(Math.pow(this.mouseEvents[i].x - this.mouseEvents[i-1].x, 2) + Math.pow(this.mouseEvents[i].y - this.mouseEvents[i-1].y, 2));
        }
        const avgMouseSpeed = this.mouseEvents.length > 1 ? totalDist / (this.mouseEvents[this.mouseEvents.length-1].ts - this.mouseEvents[0].ts) : 0;

        return {
            avg_dwell_time: avgDwell,
            std_dwell_time: std(dwells, avgDwell),
            avg_flight_time: avgFlight,
            std_flight_time: flights.length ? std(flights, avgFlight) : 0,
            typing_speed: keystrokes.length / ((keystrokes[keystrokes.length-1].ts - keystrokes[0].ts) / 1000),
            avg_mouse_speed: avgMouseSpeed * 100
        };
    }

    async sendData() {
        const features = this.calculateFeatures();
        if (!features) return;
        try {
            const res = await fetch('/behavioral/analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(features)
            });
            const data = await res.json();
            if (window.updateRiskUI) window.updateRiskUI(data.risk_score);
            if (data.action === "terminate") {
                alert("Security Alert: Session terminated due to behavioral anomaly.");
                window.location.href = '/logout';
            }
        } catch (err) { console.error("Sync error", err); }
    }
}
const collector = new BehavioralCollector();
