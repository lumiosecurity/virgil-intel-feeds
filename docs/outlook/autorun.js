// Virgil for Outlook — Autorun Event Handler
// Fires automatically when the user reads an email.
// Scans all links, shows notification if dangerous ones found.

Office.onReady(function () {
  Office.actions.associate("onMessageRead", onMessageRead);
  Office.actions.associate("onNewCompose", onNewCompose);
  Office.actions.associate("showTaskpane", showTaskpane);
});

function onMessageRead(event) {
  var item = Office.context.mailbox.item;

  item.body.getAsync(Office.CoercionType.Html, function (bodyResult) {
    if (bodyResult.status !== Office.AsyncResultStatus.Succeeded) {
      event.completed();
      return;
    }

    var html = bodyResult.value;
    var links = Virgil.extractLinksFromHtml(html);

    if (links.length === 0) {
      event.completed();
      return;
    }

    // Get sender and subject for context
    var sender = '';
    var subject = '';
    try {
      sender = item.from ? item.from.emailAddress : '';
      subject = item.subject || '';
    } catch (e) {}

    Virgil.scanLinks(links, sender, subject)
      .then(function (results) {
        // Classify results
        var dangerous = [];
        var suspicious = [];

        for (var i = 0; i < results.length; i++) {
          var verdict = Virgil.classifyResult(results[i]);
          results[i]._verdict = verdict;
          if (verdict === 'dangerous') dangerous.push(results[i]);
          else if (verdict === 'suspicious') suspicious.push(results[i]);
        }

        // Store results for taskpane
        try {
          Office.context.roamingSettings.set('virgilLastScan', JSON.stringify({
            results: results,
            links: links,
            sender: sender,
            subject: subject,
            scannedAt: new Date().toISOString(),
            dangerousCount: dangerous.length,
            suspiciousCount: suspicious.length,
          }));
          Office.context.roamingSettings.saveAsync();
        } catch (e) {}

        // Post behavioral bridge context for dangerous URLs
        if (dangerous.length > 0) {
          var flaggedUrls = dangerous.map(function (r) { return r.url; });
          Virgil.postEmailContext(flaggedUrls, sender, subject);
        }

        // Show notification
        if (dangerous.length > 0) {
          showNotification(item,
            '\u26a0\ufe0f Virgil: ' + dangerous.length + ' dangerous link' +
            (dangerous.length > 1 ? 's' : '') + ' detected — click Virgil in the toolbar for details',
            true
          );
        } else if (suspicious.length > 0) {
          showNotification(item,
            'Virgil: ' + suspicious.length + ' link' +
            (suspicious.length > 1 ? 's look' : ' looks') +
            ' suspicious — click Virgil in the toolbar for details',
            false
          );
        }

        event.completed();
      })
      .catch(function (err) {
        console.error('[Virgil] Scan failed:', err);
        event.completed();
      });
  });
}

function onNewCompose(event) {
  // Future: check if composing/forwarding an email with flagged links
  event.completed();
}

function showTaskpane(event) {
  // This action is bound to the ribbon button
  // The runtime system handles opening the taskpane automatically
  event.completed();
}

function showNotification(item, message, persistent) {
  try {
    item.notificationMessages.replaceAsync('virgilScan', {
      type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
      icon: 'icon16',
      message: message,
      persistent: !!persistent,
    }, function (result) {
      if (result.status !== Office.AsyncResultStatus.Succeeded) {
        console.debug('[Virgil] Notification failed:', result.error);
      }
    });
  } catch (e) {
    console.debug('[Virgil] Notification error:', e);
  }
}
