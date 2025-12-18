// ============================================
// UEBA Dashboard - Core JavaScript
// ============================================

// Theme Management
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
    
    // Update charts if they exist
    if (window.updateChartsTheme) {
        window.updateChartsTheme(newTheme);
    }
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('themeIcon');
    if (icon) {
        // Use SVG icons instead of emojis
        if (theme === 'dark') {
            icon.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
        } else {
            icon.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
        }
    }
}

// WebSocket Connection
let ws = null;
let wsReconnectTimer = null;

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/events`;
    
    try {
        ws = new WebSocket(wsUrl);
        
        ws.onopen = () => {
            updateStatus(true);
            clearTimeout(wsReconnectTimer);
        };
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'new_event' && window.handleNewEvent) {
                window.handleNewEvent(data.event);
            } else if (data.type === 'new_alert' && window.handleNewAlert) {
                window.handleNewAlert(data.alert);
            }
        };
        
        ws.onclose = () => {
            updateStatus(false);
            wsReconnectTimer = setTimeout(connectWebSocket, 3000);
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            updateStatus(false);
        };
    } catch (e) {
        console.error('Failed to connect WebSocket:', e);
        updateStatus(false);
    }
}

function updateStatus(connected) {
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    
    if (dot && text) {
        if (connected) {
            dot.classList.remove('disconnected');
            text.textContent = 'Live';
        } else {
            dot.classList.add('disconnected');
            text.textContent = 'Reconnecting...';
        }
    }
}

// Chart Utilities
function createTimelineChart(canvasId, data, label, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) {
        console.error(`Canvas element not found: ${canvasId}`);
        return null;
    }
    
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const gridColor = isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.12)';
    const textColor = isDark ? '#9aa0a6' : '#374151';  // Darker text for light mode readability
    
    const labels = Object.keys(data || {});
    const values = labels.map(key => data[key] || 0);
    
    // Handle empty data
    if (labels.length === 0) {
        console.warn(`No data for chart: ${canvasId}`);
        // Show placeholder with zero data
        labels.push(new Date().toISOString());
        values.push(0);
    }
    
    // Detect if data spans multiple days
    let spansMultipleDays = false;
    if (labels.length >= 2) {
        const firstDate = new Date(labels[0]);
        const lastDate = new Date(labels[labels.length - 1]);
        const daysDiff = (lastDate - firstDate) / (1000 * 60 * 60 * 24);
        spansMultipleDays = daysDiff > 1;
    }
    
    // Format labels: include date for multi-day ranges, otherwise just time
    const formattedLabels = labels.map(label => {
        const date = new Date(label);
        if (spansMultipleDays) {
            // For multi-day: show month/day + hour
            return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + 
                   ' ' + date.toLocaleTimeString('en-US', { hour: '2-digit', hour12: false }) + ':00';
        } else {
            // For single day: show just time
            return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
        }
    });
    
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: formattedLabels,
            datasets: [{
                label: label,
                data: values,
                borderColor: color,
                backgroundColor: color + '20',
                fill: true,
                tension: 0.4,
                pointRadius: 3,
                pointBackgroundColor: color,
                pointBorderColor: color,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            // Animation settings for smooth updates
            animation: {
                duration: 400,
                easing: 'easeOutQuart'
            },
            transitions: {
                active: {
                    animation: {
                        duration: 200
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: isDark ? '#0b1020' : '#ffffff',
                    titleColor: isDark ? '#e8eaed' : '#1a1a1a',
                    bodyColor: isDark ? '#9aa0a6' : '#5f6368',
                    borderColor: isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: {
                        color: gridColor,
                        drawBorder: false
                    },
                    ticks: {
                        color: textColor,
                        maxRotation: 45,
                        font: {
                            size: 11
                        }
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: gridColor,
                        drawBorder: false
                    },
                    ticks: {
                        color: textColor,
                        font: {
                            size: 11
                        }
                    }
                }
            }
        }
    });
}

function createDonutChart(canvasId, data, colors) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#9aa0a6' : '#374151';  // Darker for light mode
    
    const labels = Object.keys(data);
    const values = Object.values(data);
    
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            // Animation settings for smooth updates without full reset
            animation: {
                duration: 400,  // Short animation for responsiveness
                easing: 'easeOutQuart'
            },
            transitions: {
                active: {
                    animation: {
                        duration: 300  // Smooth transition when updating data
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: textColor,
                        padding: 15,
                        font: {
                            size: 11
                        }
                    }
                },
                tooltip: {
                    backgroundColor: isDark ? '#0b1020' : '#ffffff',
                    titleColor: isDark ? '#e8eaed' : '#1a1a1a',
                    bodyColor: isDark ? '#9aa0a6' : '#374151',
                    borderColor: isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.15)',
                    borderWidth: 1
                }
            }
        }
    });
}

// Format numbers
function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

// Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

// Escape HTML
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    
    // Theme toggle
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
    
    // Connect WebSocket
    connectWebSocket();
    
    // Time range selector
    const timeRangeSelect = document.getElementById('timeRangeSelect');
    if (timeRangeSelect && window.handleTimeRangeChange) {
        timeRangeSelect.addEventListener('change', (e) => {
            window.handleTimeRangeChange(e.target.value);
        });
    }
});

// Export for use in page-specific scripts
window.dashboardUtils = {
    formatNumber,
    formatTimestamp,
    escapeHtml,
    createTimelineChart,
    createDonutChart
};

