using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using System.Collections.Concurrent;
using UUIDNext;

[Authorize]
public class SignalingHub : Hub
{
    private readonly ILogger<SignalingHub> _logger;
    private static readonly ConcurrentDictionary<string, string> _mapping = new ConcurrentDictionary<string, string>();
    private ConcurrentBag<string> _groups = new ConcurrentBag<string>();

    public SignalingHub(ILogger<SignalingHub> logger)
    {
        _logger = logger;
    }

    public async Task JoinRoom(string roomId)
    {
        _logger.LogInformation($"trying to join {roomId}");
        
        if (_mapping.ContainsKey(roomId))
        {
            var creatorConnectionId = _mapping[roomId];
            _logger.LogInformation($"found creator connection {creatorConnectionId}");

            await Groups.AddToGroupAsync(Context.ConnectionId, roomId);
            await Groups.AddToGroupAsync(creatorConnectionId, roomId);
            _groups.Add(roomId);

            await Clients.Client(creatorConnectionId).SendAsync("UserJoined");
        }
        else
        {
            _logger.LogWarning($"room {roomId} doesn't exist");
        }
    }

    public async Task CreateRoom()
    {
        var roomId = Uuid.NewRandom().ToString();
        _logger.LogInformation($"creating room with id: {roomId}");
        
        if (_mapping.TryAdd(roomId, Context.ConnectionId))
        {
            _logger.LogInformation($"room {roomId} created successfully");
            await Groups.AddToGroupAsync(Context.ConnectionId, roomId);
            _groups.Add(roomId);
            await Clients.Caller.SendAsync("RoomCreated", roomId);
        }
    }

    public async Task SendSignal(string roomId, object signalData)
    {
        _logger.LogInformation($"Received signal in room {roomId} from {Context.ConnectionId}");
        _logger.LogInformation($"Signal data: {signalData}");
        
        // Send to all clients in the group except the sender
        await Clients.OthersInGroup(roomId).SendAsync("ReceiveSignal", signalData);
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        var roomsToRemove = _mapping.Where(kvp => kvp.Value == Context.ConnectionId)
                                  .Select(kvp => kvp.Key)
                                  .ToList();

        foreach (var roomId in roomsToRemove)
        {
            _mapping.TryRemove(roomId, out _);
            _logger.LogInformation($"Removed room {roomId} due to disconnect");
        }

        await base.OnDisconnectedAsync(exception);
    }
}