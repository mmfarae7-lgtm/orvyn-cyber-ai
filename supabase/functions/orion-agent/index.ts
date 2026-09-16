import { createClient } from 'npm:@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Client-Info, Apikey',
};

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  const url = new URL(req.url);
  const path = url.pathname.split('/').pop() ?? '';

  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  );

  try {
    // GET /orion-agent/poll — agent fetches next pending task
    if (req.method === 'GET' && path === 'poll') {
      const agentId = url.searchParams.get('agent_id') ?? 'default';

      const { data: task } = await supabase
        .from('agent_tasks')
        .select('*')
        .eq('status', 'pending')
        .order('created_at', { ascending: true })
        .limit(1)
        .maybeSingle();

      if (!task) {
        return new Response(
          JSON.stringify({ task: null }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      await supabase
        .from('agent_tasks')
        .update({
          status: 'running',
          assigned_to: agentId,
          started_at: new Date().toISOString(),
        })
        .eq('id', task.id);

      return new Response(
        JSON.stringify({ task }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // GET /orion-agent/status/:taskId — check task status
    if (req.method === 'GET' && path === 'status') {
      const taskId = url.searchParams.get('task_id');
      if (!taskId) {
        return new Response(
          JSON.stringify({ error: 'task_id required' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      const { data: task } = await supabase
        .from('agent_tasks')
        .select('*')
        .eq('id', taskId)
        .maybeSingle();

      return new Response(
        JSON.stringify({ task }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // POST /orion-agent/submit — create a new task (from web UI)
    if (req.method === 'POST' && path === 'submit') {
      const authHeader = req.headers.get('Authorization') ?? '';
      const token = authHeader.replace('Bearer ', '');

      const { data: userData } = await supabase.auth.getUser(token);
      const userId = userData.user?.id;

      if (!userId) {
        return new Response(
          JSON.stringify({ error: 'Unauthorized' }),
          { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      const body = await req.json();
      const { tool, target, options, scanId } = body;

      if (!tool || !target) {
        return new Response(
          JSON.stringify({ error: 'tool and target are required' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      const { data: task, error } = await supabase
        .from('agent_tasks')
        .insert({
          user_id: userId,
          scan_id: scanId ?? null,
          tool,
          target,
          options: options ?? {},
          status: 'pending',
        })
        .select()
        .single();

      if (error) {
        return new Response(
          JSON.stringify({ error: error.message }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      return new Response(
        JSON.stringify({ task }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // POST /orion-agent/result — agent submits task result
    if (req.method === 'POST' && path === 'result') {
      const body = await req.json();
      const { taskId, status, output, rawOutput, error, agentId } = body;

      if (!taskId) {
        return new Response(
          JSON.stringify({ error: 'taskId required' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // Only allow the agent that is assigned to this task to submit the result
      const { data: existing } = await supabase
        .from('agent_tasks')
        .select('assigned_to, status')
        .eq('id', taskId)
        .maybeSingle();

      if (!existing) {
        return new Response(
          JSON.stringify({ error: 'Task not found' }),
          { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      if (agentId && existing.assigned_to && existing.assigned_to !== agentId) {
        return new Response(
          JSON.stringify({ error: 'Not authorized to update this task' }),
          { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      if (!existing.assigned_to && status !== 'failed') {
        return new Response(
          JSON.stringify({ error: 'Task has not been claimed by an agent' }),
          { status: 409, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      const updateData: Record<string, unknown> = {
        status: status ?? 'completed',
        completed_at: new Date().toISOString(),
      };
      if (output) updateData.output = output;
      if (rawOutput !== undefined) updateData.raw_output = rawOutput;
      if (error) updateData.error = error;

      const { data: task, error: updateError } = await supabase
        .from('agent_tasks')
        .update(updateData)
        .eq('id', taskId)
        .select()
        .single();

      if (updateError) {
        return new Response(
          JSON.stringify({ error: updateError.message }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // If linked to a scan, update the scan record too
      if (task.scan_id) {
        await supabase
          .from('scans')
          .update({
            status: status === 'completed' ? 'completed' : 'failed',
            results: output ?? {},
            completed_at: new Date().toISOString(),
          })
          .eq('id', task.scan_id);
      }

      return new Response(
        JSON.stringify({ success: true, task }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // GET /orion-agent/tasks — list user's tasks
    if (req.method === 'GET' && path === 'tasks') {
      const authHeader = req.headers.get('Authorization') ?? '';
      const token = authHeader.replace('Bearer ', '');
      const { data: userData } = await supabase.auth.getUser(token);
      const userId = userData.user?.id;

      if (!userId) {
        return new Response(
          JSON.stringify({ error: 'Unauthorized' }),
          { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      const { data: tasks } = await supabase
        .from('agent_tasks')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(20);

      return new Response(
        JSON.stringify({ tasks }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    return new Response(
      JSON.stringify({ error: 'Unknown endpoint' }),
      { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: err instanceof Error ? err.message : 'Unknown error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
